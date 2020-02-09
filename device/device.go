/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	DeviceRoutineNumberPerCPU     = 3
	DeviceRoutineNumberAdditional = 2
)

type Device struct {
	isUp     AtomicBool // device is (going) up
	isClosed AtomicBool // device is closed? (acting as guard)
	log      *Logger

	// synchronized resources (locks acquired in order)

	state struct {
		starting sync.WaitGroup
		stopping sync.WaitGroup
		sync.Mutex
		changing AtomicBool
		current  bool
	}

	net struct {
		starting sync.WaitGroup
		stopping sync.WaitGroup
		sync.RWMutex
		bind   Bind   // bind interface
		port   uint16 // listening port
		fwmark uint32 // mark value (0 = disabled)
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex
		keyMap map[NoisePublicKey]*Peer
	}

	// unprotected / "self-synchronising resources"

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	rate struct {
		underLoadUntil atomic.Value
		limiter        ratelimiter.Ratelimiter
	}

	pool struct {
		messageBufferPool        *sync.Pool
		messageBufferReuseChan   chan *[MaxMessageSize]byte
		inboundElementPool       *sync.Pool
		inboundElementReuseChan  chan *QueueInboundElement
		outboundElementPool      *sync.Pool
		outboundElementReuseChan chan *QueueOutboundElement
	}

	queue struct {
		encryption chan *QueueOutboundElement
		decryption chan *QueueInboundElement
		handshake  chan QueueHandshakeElement
	}

	signals struct {
		stop chan struct{}
	}

	tun struct {
		device tun.Device
		mtu    int32
	}
}

/* Converts the peer into a "zombie", which remains in the peer map,
 * but processes no packets and does not exists in the routing table.
 *
 * Must hold device.peers.Mutex
 */
func unsafeRemovePeer(device *Device, peer *Peer, key NoisePublicKey) {

	// stop routing and processing of packets

	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map

	delete(device.peers.keyMap, key)
}

func deviceUpdateState(device *Device) {

	// check if state already being updated (guard)

	if device.state.changing.Swap(true) {
		return
	}

	// compare to current state of device

	device.state.Lock()

	newIsUp := device.isUp.Get()

	if newIsUp == device.state.current {
		device.state.changing.Set(false)
		device.state.Unlock()
		return
	}

	// change state of device

	switch newIsUp {
	case true:
		if err := device.BindUpdate(); err != nil {
			device.log.Error.Printf("Unable to update bind: %v\n", err)
			device.isUp.Set(false)
			break
		}
		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Start()
			if peer.persistentKeepaliveInterval > 0 {
				peer.SendKeepalive()
			}
		}
		device.peers.RUnlock()

	case false:
		device.BindClose()
		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Stop()
		}
		device.peers.RUnlock()
	}

	// update state variables

	device.state.current = newIsUp
	device.state.changing.Set(false)
	device.state.Unlock()

	// check for state change in the mean time

	deviceUpdateState(device)
}

func (device *Device) Up() {

	// closed device cannot be brought up

	if device.isClosed.Get() {
		return
	}

	device.isUp.Set(true)
	deviceUpdateState(device)
}

func (device *Device) Down() {
	device.isUp.Set(false)
	deviceUpdateState(device)
}

func (device *Device) IsUnderLoad() bool {

	// check if currently under load

	now := time.Now()
	underLoad := len(device.queue.handshake) >= UnderLoadQueueSize
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime))
		return true
	}

	// check if recently under load

	until := device.rate.underLoadUntil.Load().(time.Time)
	return until.After(now)
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			unsafeRemovePeer(device, peer, key)
		}
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		if isZero(handshake.precomputedStaticStatic[:]) {
			panic("an invalid peer public key made it into the configuration")
		}
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(tunDevice tun.Device, logger *Logger) *Device {
	device := new(Device)

	device.isUp.Set(false)
	device.isClosed.Set(false)

	device.log = logger

	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		logger.Error.Println("Trouble determining MTU, assuming default:", err)
		mtu = DefaultMTU
	}
	device.tun.mtu = int32(mtu)

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)

	device.rate.limiter.Init()
	device.rate.underLoadUntil.Store(time.Time{})

	device.indexTable.Init()
	device.allowedips.Reset()

	device.PopulatePools()

	// create queues

	device.queue.handshake = make(chan QueueHandshakeElement, QueueHandshakeSize)
	device.queue.encryption = make(chan *QueueOutboundElement, QueueOutboundSize)
	device.queue.decryption = make(chan *QueueInboundElement, QueueInboundSize)

	// prepare signals

	device.signals.stop = make(chan struct{})

	// prepare net

	device.net.port = 0
	device.net.bind = nil

	// start workers

	cpus := runtime.NumCPU()
	device.state.starting.Wait()
	device.state.stopping.Wait()
	device.state.stopping.Add(DeviceRoutineNumberPerCPU*cpus + DeviceRoutineNumberAdditional)
	device.state.starting.Add(DeviceRoutineNumberPerCPU*cpus + DeviceRoutineNumberAdditional)
	for i := 0; i < cpus; i += 1 {
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	device.state.starting.Wait()

	return device
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		unsafeRemovePeer(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		unsafeRemovePeer(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

func (device *Device) FlushPacketQueues() {
	for {
		select {
		case elem, ok := <-device.queue.decryption:
			if ok {
				elem.Drop()
			}
		case elem, ok := <-device.queue.encryption:
			if ok {
				elem.Drop()
			}
		case <-device.queue.handshake:
		default:
			return
		}
	}

}

func (device *Device) Close() {
	if device.isClosed.Swap(true) {
		return
	}

	device.state.starting.Wait()

	device.log.Info.Println("Device closing")
	device.state.changing.Set(true)
	device.state.Lock()
	defer device.state.Unlock()

	device.tun.device.Close()
	device.BindClose()

	device.isUp.Set(false)

	close(device.signals.stop)

	device.RemoveAllPeers()

	device.state.stopping.Wait()
	device.FlushPacketQueues()

	device.rate.limiter.Close()

	device.state.changing.Set(false)
	device.log.Info.Println("Interface closed")
}

func (device *Device) Wait() chan struct{} {
	return device.signals.stop
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if device.isClosed.Get() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

const WG_DEVICE_SBOX_SIZE uint16 = 256
var sbox_counter uint16 = 0

var HeaderRandomSBox = [WG_DEVICE_SBOX_SIZE]uint32{
	0x94E7, 0x8778, 0x49E0, 0xB601,
	0x6CE4, 0xF67C, 0x23C6, 0x0B28,
	0x62F7, 0xCF00, 0x05E7, 0x32A2,
	0x0BD6, 0x7106, 0x17E1, 0xC823,
	0x2A58, 0xD9E5, 0x1BC0, 0xA0CD,
	0x8291, 0x965F, 0xAE89, 0x4DA2,
	0x0544, 0x4B7E, 0x21D4, 0x831E,
	0xFAB0, 0x89E3, 0x4143, 0x84C5,
	0xB80B, 0xF1FA, 0xF98B, 0x124E,
	0x1ABA, 0xD266, 0x4DAB, 0x6AA6,
	0x81B9, 0x7EDB, 0x39A9, 0x91CC,
	0xCC87, 0x7B75, 0x43F9, 0xD2E3,
	0xF421, 0x5D72, 0x4095, 0xB7B2,
	0x8E3F, 0x5EAC, 0x86AC, 0x8495,
	0xAA81, 0xC2BD, 0x380B, 0x42A8,
	0x014B, 0x3994, 0x1C44, 0x4A4D,
	0x123F, 0x556E, 0x469F, 0xFE01,
	0x44A7, 0x1300, 0x261E, 0xD871,
	0x5083, 0xBFA4, 0xED13, 0x35EE,
	0x6502, 0x0EB7, 0xC762, 0xB261,
	0x3700, 0x577C, 0xB691, 0x2187,
	0xA6B6, 0x0095, 0x2774, 0x09C3,
	0x8312, 0xBC04, 0x531F, 0x1A82,
	0xFC51, 0x3BA4, 0xE2A6, 0x2896,
	0x2FBE, 0x5B33, 0x3EE2, 0x40A7,
	0x46B9, 0x5D11, 0x4105, 0xB597,
	0xE73C, 0x36EE, 0x5C65, 0xA586,
	0x4548, 0xC307, 0x4754, 0xC0B5,
	0xADB8, 0x95F7, 0xA473, 0x3C6A,
	0x358D, 0xB51E, 0x8DEE, 0x3E00,
	0xBB5F, 0x6DD3, 0xB9B0, 0xE0D1,
	0x852B, 0xC5C6, 0xBA40, 0x19E3,
	0x0F63, 0x4781, 0xF4E3, 0xB6AE,
	0xF18A, 0xB184, 0xADDF, 0xB707,
	0xE759, 0x15C6, 0x9FDC, 0xFA8A,
	0xF2F0, 0x9BEB, 0xDE8E, 0x7DB6,
	0xB532, 0xF03A, 0xD640, 0x4A5D,
	0x163C, 0x2C20, 0xE853, 0x8202,
	0x24E8, 0x5479, 0xAF09, 0x9FAD,
	0x8B6C, 0x8562, 0x78A7, 0xA08E,
	0x8E23, 0x8F5E, 0xC5A6, 0x1326,
	0x9A9F, 0xBE72, 0xC1BA, 0xEB5D,
	0xA52D, 0xBBF7, 0x2DE0, 0x86C7,
	0x105D, 0x4E91, 0xF4B5, 0x9EBD,
	0x95F3, 0xBF54, 0x8643, 0x1548,
	0xD583, 0x1D8A, 0x5814, 0x77F9,
	0x3984, 0x850F, 0xED67, 0xB6DE,
	0x7F97, 0x95FE, 0x666A, 0x3ED8,
	0xCDE0, 0x4F7C, 0x5E0E, 0x4805,
	0xEF10, 0x5018, 0x0FB8, 0x9353,
	0x24AF, 0x22CA, 0xA439, 0x5CA5,
	0x0F0E, 0xA21F, 0x4A2C, 0x0856,
	0xB0C2, 0x85D8, 0xAFC4, 0xF50D,
	0xDFCB, 0x97F2, 0x383F, 0xB8B8,
	0xD217, 0x1ED8, 0x0175, 0x612D,
	0x788D, 0xFC2D, 0x5415, 0x9CA8,
	0xD2EA, 0x627A, 0x79A5, 0x1764,
	0x743E, 0xB894, 0x6010, 0xC44A,
	0x661B, 0x33E6, 0x8328, 0xD65A,
	0x638D, 0xD165, 0x0CBF, 0x617F,
	0x71FA, 0xF431, 0x2702, 0x093A,
	0x5ECB, 0xD44F, 0xED94, 0x9333,
	0xEB71, 0x75B5, 0x9A4E, 0x94FD,
	0x3E43, 0xF61A, 0x1E43, 0x7980,
}

func GetRandomForHeader() (random uint32) {
	defer func() {
		sbox_counter += 1
		if (sbox_counter >= WG_DEVICE_SBOX_SIZE) {
			sbox_counter = 0;
		}
	}()

	return HeaderRandomSBox[sbox_counter]
}
