/* 
 * lixingke3650@gmail.com
 */

package device

const WG_DEVICE_SBOX_SIZE uint16 = 1024
var sbox_counter uint16 = 0

var HeaderRandomSBox = [WG_DEVICE_SBOX_SIZE]uint32 {
	0xF74F, 0xDF66, 0xF429, 0xA337, 0x47C5, 0xAACA, 0x1BDC, 0x1909, 
	0xC99E, 0x8393, 0x3C5E, 0x5D8A, 0x3D7B, 0x9AA1, 0x2658, 0x7155, 
	0x74DD, 0x23DA, 0x7B29, 0x2D47, 0x76C5, 0x57B0, 0xE451, 0xC2ED, 
	0x2B76, 0x8AD8, 0xF4A6, 0xBFE8, 0x6FE6, 0xAD48, 0x93E6, 0xC97A, 
	0x3E92, 0xE58B, 0xDB9A, 0xF603, 0xECCF, 0xF698, 0x0D1C, 0x954A, 
	0xEC62, 0x096D, 0x871D, 0x04C1, 0xFBE2, 0x33E6, 0x308A, 0x21BB, 
	0xFBCD, 0x06D9, 0xC8FA, 0x5FE3, 0x9F50, 0xF1A2, 0xC1B9, 0x01C0, 
	0xD8B8, 0x3A14, 0xE84A, 0x4A4A, 0x5AEA, 0xC740, 0x2A01, 0x7421, 
	0x0D08, 0x2DA7, 0x7454, 0xEBE5, 0x169F, 0x5080, 0x92A7, 0x247B, 
	0xB648, 0xE4D5, 0xA0F4, 0x7D56, 0xF0D2, 0x8C5D, 0x4464, 0x6C51, 
	0xFA22, 0x0AB9, 0x95BB, 0x44FF, 0x4135, 0x4E3F, 0x8D56, 0xDF29, 
	0x1E06, 0xB786, 0xC6BB, 0x5EB4, 0x06E3, 0x497F, 0x20F2, 0xAA27, 
	0x00B3, 0x5C7D, 0x8308, 0x7EF0, 0xFE2A, 0xD254, 0xEFA7, 0x3AC8, 
	0x422B, 0x960C, 0xE469, 0xFE9B, 0x9A36, 0x9FAF, 0xB058, 0x206A, 
	0x19B3, 0x87D2, 0x2467, 0x20B1, 0x588D, 0x3B80, 0x62D8, 0xD14B, 
	0x8020, 0xE0A5, 0xCED9, 0x4482, 0x394E, 0x3B87, 0x4C5F, 0xBADA, 
	0x5E37, 0x787F, 0xD1AF, 0xACD0, 0x18B4, 0x3BAF, 0x3323, 0x2B32, 
	0xF6A8, 0xAFD4, 0xA708, 0x1016, 0x4366, 0xF5C7, 0x9004, 0x4CBF, 
	0x1854, 0xC8D3, 0x94CC, 0x4AA5, 0x53BD, 0xF4C9, 0xD115, 0x501C, 
	0xED1A, 0x1909, 0xEE9B, 0x366A, 0x8229, 0xAA8C, 0xD817, 0x3B3D, 
	0x04B3, 0x4608, 0x3269, 0x13C3, 0x6DCE, 0xCC4F, 0x4243, 0x52B2, 
	0x25F8, 0x422D, 0x6169, 0xD918, 0xBFFD, 0x0994, 0x9BCC, 0x2ECE, 
	0xF7EE, 0x37D2, 0xEB66, 0x7183, 0x985A, 0xCB86, 0xD9AC, 0xF654, 
	0xB311, 0x85BE, 0xBBBC, 0x1A53, 0x7C90, 0xEFF8, 0xF956, 0xCD7C, 
	0x2454, 0x2E2E, 0x13CF, 0x291E, 0x8EFB, 0x6FC0, 0xE9CB, 0x2893, 
	0xD7A0, 0x724F, 0xC203, 0xD8D9, 0x18BE, 0x8630, 0x6EFC, 0xBCE4, 
	0x0BC0, 0x5E6A, 0xDA9B, 0x12D9, 0xB6FF, 0x23FA, 0xA084, 0xE3D0, 
	0x6F79, 0xDB4C, 0x1474, 0x03F6, 0xC18F, 0xD66F, 0xFF4D, 0x0159, 
	0xFF87, 0x391A, 0x6F6A, 0x9572, 0x93E8, 0xF298, 0x0C85, 0x50C8, 
	0xECD4, 0xAEA2, 0x5842, 0x8D57, 0x30E5, 0x439C, 0x5024, 0x12A8, 
	0xA548, 0xA520, 0xA009, 0x8488, 0x5794, 0x8E29, 0xCD04, 0xC78D, 
	0x1569, 0xE4B1, 0x97B6, 0xEEEA, 0x7D0A, 0xF243, 0xF813, 0x1629, 
	0x67BE, 0x80BF, 0x049D, 0x3758, 0x36E1, 0x7DCA, 0xAED1, 0xA601, 
	0x97A4, 0xBA08, 0x6F0F, 0xBC1A, 0x8BF9, 0x3EF3, 0x2732, 0xD2F1, 
	0xDE42, 0x6939, 0xEC31, 0xC0F9, 0x0429, 0xE311, 0x703A, 0xDA01, 
	0xB17D, 0xA69D, 0x1B1C, 0xCCB0, 0x17B5, 0x7310, 0x1A04, 0x3077, 
	0xFE4A, 0x64C1, 0xBF54, 0x8284, 0x39D6, 0x2AD9, 0x7B24, 0xD1FE, 
	0x5E57, 0xD08C, 0x3FCE, 0xF7D0, 0x63DD, 0x1366, 0x532A, 0x2C1F, 
	0xCD06, 0x1C55, 0xCA03, 0xF87F, 0x37A3, 0x64EE, 0xE222, 0x60D0, 
	0x7AA0, 0x3B64, 0x4F7C, 0x2C38, 0x3279, 0x717A, 0x87FA, 0xC00D, 
	0x6DBE, 0xFE4D, 0xE96B, 0x1A3E, 0x6D1D, 0x4C33, 0xF883, 0x3046, 
	0x3DA3, 0x883E, 0xBE32, 0xB01A, 0xE572, 0xD06C, 0x2791, 0x1EDF, 
	0xD6D2, 0xD94A, 0x3CCB, 0xC1A1, 0xA033, 0x7853, 0x014A, 0xEAB5, 
	0xFC95, 0x2BC4, 0xDF5E, 0x0B69, 0x6A6C, 0xDEC8, 0x6DCE, 0x6968, 
	0x63B2, 0xBBA4, 0x9091, 0x8EB1, 0xB2CB, 0x06DA, 0x200D, 0x1F57, 
	0x6B95, 0xAD46, 0x035B, 0xD2B4, 0x7CB5, 0x2CEA, 0xD90A, 0x6EA5, 
	0x0C4D, 0xE1C6, 0xCD10, 0xF73A, 0x26D4, 0x01E8, 0x5F9D, 0xE6D9, 
	0xBBA6, 0xF623, 0x4102, 0x7D21, 0xE900, 0x5DE6, 0xDF54, 0xE47F, 
	0x458B, 0xCC76, 0x5461, 0xF1DC, 0x443D, 0x31AE, 0x442F, 0xFEAD, 
	0xA974, 0x6628, 0xBFCC, 0x2351, 0xDC8C, 0xBEE9, 0x40F4, 0x84BF, 
	0xFC1A, 0x0E23, 0xAE8C, 0x41AE, 0xA099, 0x837C, 0xDC1D, 0x872F, 
	0x2EB9, 0xCBDF, 0x7516, 0x28DC, 0x2F44, 0x18BC, 0xE3C4, 0xF6DE, 
	0xDB64, 0x2C26, 0x4957, 0xDEC8, 0x2234, 0x8A7A, 0x2FEE, 0xB2B6, 
	0xF565, 0xD285, 0x428B, 0x3BC6, 0xA91F, 0x7CF6, 0x6E58, 0x3A4F, 
	0x0533, 0x8DC0, 0x3FC7, 0xE8BD, 0x11B3, 0xB12F, 0x1969, 0xB974, 
	0x6EFD, 0xC88F, 0x7E0A, 0x8325, 0xB238, 0x0926, 0x6201, 0x47C1, 
	0xF49E, 0xD6AA, 0xBE8C, 0xF895, 0x9CE0, 0x7201, 0xD647, 0xD9DB, 
	0xF7E5, 0xF28C, 0x7558, 0xFAB7, 0xD427, 0x796C, 0x25CE, 0x8C5E, 
	0x5B13, 0x5B61, 0xA498, 0xF039, 0xBD60, 0xFFA4, 0xA75B, 0x235F, 
	0xA022, 0x70F9, 0x912D, 0xF5C7, 0xCBD1, 0x8BCF, 0x41EB, 0x0361, 
	0x0B08, 0xFC8B, 0xF4B9, 0xED5A, 0x808D, 0x8190, 0x42A3, 0x9B3C, 
	0xBCB4, 0x6EF2, 0xC349, 0x4A45, 0x3783, 0x217A, 0xAE3D, 0xA3FA, 
	0xB480, 0x0379, 0x208D, 0xF9AE, 0x9580, 0x73E4, 0x916A, 0x5C63, 
	0xC64A, 0xC62A, 0x70EE, 0xAEFD, 0xF5E0, 0xC39A, 0x4C79, 0x4B0F, 
	0x9821, 0x43B9, 0x927E, 0x12D9, 0xFB84, 0xF0A4, 0x552C, 0xDFCD, 
	0x7977, 0x4017, 0x6390, 0x4749, 0x4A59, 0x1556, 0x1784, 0x88A3, 
	0x0BBA, 0x09A2, 0x15E2, 0x6815, 0x5673, 0x0DBC, 0x282E, 0x6CD5, 
	0x5A21, 0x283F, 0xAF66, 0x1D04, 0x096D, 0xADDE, 0x2E2D, 0xAAF1, 
	0xB50B, 0x1614, 0x24E8, 0x1AD2, 0x9A35, 0x017D, 0x71A9, 0xCAA2, 
	0x3452, 0x7412, 0xDF28, 0x571D, 0x239F, 0xFEA1, 0xC226, 0xEBF7, 
	0x5254, 0xF5C4, 0xF84D, 0x217B, 0x8846, 0xBE63, 0x5CAB, 0xA12E, 
	0xE958, 0x0D0F, 0x6D7E, 0xCDC3, 0x3319, 0x9DF7, 0x326E, 0x8F65, 
	0x6FED, 0x1C6F, 0x2F18, 0xAA15, 0x0B5E, 0x37FD, 0xD0F5, 0x0C67, 
	0x6710, 0xE697, 0x501A, 0xFA52, 0x5C78, 0xC828, 0x4861, 0x51DB, 
	0x3389, 0x4CB8, 0x3F24, 0x5483, 0xF9D8, 0x3C6F, 0x733A, 0x46BF, 
	0xEA7B, 0xED47, 0xA668, 0x4226, 0xA889, 0xBA1C, 0x70CC, 0x7C67, 
	0xC747, 0xC78C, 0xFA54, 0x506D, 0xF6B0, 0x11BA, 0xA802, 0x9D05, 
	0x6DB6, 0x5CBC, 0xFB75, 0x9FE3, 0xE97A, 0xDD08, 0x9CD3, 0xFAFA, 
	0x2211, 0x4B32, 0x4E29, 0x5176, 0xD1EE, 0x8E00, 0xB1B1, 0x8F6D, 
	0x5711, 0xB1C0, 0xA9B1, 0x0B09, 0x59FD, 0x7DF6, 0xA692, 0x33A1, 
	0x5F0E, 0x497E, 0xEFD2, 0x5A01, 0x38C3, 0x2E70, 0x6671, 0x29A1, 
	0xE4E6, 0x25FF, 0xFC65, 0x1F55, 0xD70F, 0x6477, 0xCC11, 0x80DE, 
	0x0AC0, 0xB9CF, 0x5BA9, 0x8DE2, 0x604F, 0x9773, 0xEF43, 0x99B4, 
	0xAFA5, 0x0C6F, 0x104B, 0xB6FF, 0xFD1F, 0xBB9B, 0x0722, 0x53D1, 
	0x3CFF, 0x7AAC, 0xC134, 0x09D6, 0x18EC, 0x8215, 0x82E1, 0xECC9, 
	0xB34A, 0xD9FC, 0x6F8E, 0x7BCC, 0x6ABD, 0x31BF, 0x99B8, 0x16AD, 
	0xADD1, 0x52A2, 0x8550, 0xE807, 0xFB23, 0xED95, 0x4BC5, 0x75B4, 
	0x8ABB, 0x23F7, 0x01D0, 0xF835, 0x7102, 0xABBA, 0x7946, 0x07B5, 
	0xA217, 0xA503, 0xCB56, 0x3ADB, 0x5C5C, 0x6E9E, 0x19A2, 0xE8F5, 
	0xF416, 0x8401, 0x6559, 0xCDFA, 0x761D, 0xAF63, 0xEB94, 0x1BE0, 
	0xCCBE, 0x3089, 0x2772, 0x43C8, 0x3A8D, 0x6508, 0xE2E4, 0x5B0C, 
	0x0343, 0xF96D, 0xC3DF, 0xFEE3, 0x276A, 0x4020, 0xBAF7, 0xDF43, 
	0xB432, 0x23C1, 0xF6EE, 0x70A0, 0x39CF, 0xD242, 0x7C9D, 0xF3DD, 
	0x90DD, 0x0575, 0xCA53, 0x0D61, 0xED59, 0xE8E2, 0x6E3E, 0x7A95, 
	0x0CD4, 0xCCC6, 0x63E0, 0x79BC, 0x8060, 0xF12A, 0x86F4, 0x7D50, 
	0x8292, 0xDB77, 0x4B18, 0x1B65, 0xD417, 0xA887, 0x192C, 0x8D52, 
	0x6AC4, 0x19B5, 0xF4EE, 0x050D, 0x62A0, 0x9936, 0xE9C0, 0x1EBE, 
	0x7738, 0x9DA3, 0x9319, 0xD31C, 0x9D6E, 0x3486, 0xEF84, 0x9BDD, 
	0x0096, 0xB668, 0x43FD, 0xFFB6, 0x260A, 0xD33A, 0x137A, 0xCB09, 
	0xFD3E, 0x0A66, 0xA5AA, 0x5455, 0xFF61, 0x5E5B, 0x85F9, 0x80F7, 
	0x1FB9, 0xDC8B, 0x9AC3, 0x23C2, 0x2360, 0x7742, 0x4786, 0x7A2C, 
	0x7BC5, 0xA5E2, 0x9E58, 0xE1BF, 0x6920, 0x0301, 0xAF0C, 0xD08C, 
	0xC110, 0x4E9C, 0x4D73, 0xE747, 0xA8B3, 0xE5B7, 0x514F, 0xE7F4, 
	0xEE93, 0x9AAB, 0xB3E2, 0xCF97, 0x794A, 0x5C40, 0x8C0C, 0xC0C1, 
	0xA1F6, 0x9F04, 0xE912, 0x7D4E, 0xE6F5, 0xADB3, 0x1B3B, 0xDA24, 
	0x3978, 0x24FC, 0x696E, 0x9577, 0xCE5D, 0x2BCB, 0x96EA, 0x57F9, 
	0x76D9, 0x00C5, 0xF525, 0x38E3, 0x1674, 0x681D, 0xA20A, 0x9FEE, 
	0xAE34, 0x6936, 0xCDA4, 0x4F6D, 0x638E, 0x7227, 0xAC57, 0x2C03, 
	0x561E, 0x26A1, 0x2394, 0xA133, 0x2481, 0x63CE, 0x7EFC, 0x3023, 
	0x5654, 0xA17D, 0x75C6, 0x66FA, 0x36DD, 0x8F2D, 0xE0FB, 0x1CEF, 
	0x6995, 0xE879, 0xDE34, 0xC006, 0x1316, 0x15F8, 0x2436, 0x6DC0, 
	0xA69A, 0xDE51, 0x36F7, 0x882C, 0x81D7, 0x0B6D, 0x146B, 0x1E4D, 
	0xCFAF, 0x87C4, 0xEB63, 0x9F99, 0x3DA7, 0xFA27, 0xB924, 0x1576, 
	0xA46F, 0x32CB, 0x2862, 0x42E9, 0x5379, 0x3292, 0xE547, 0x13E0, 
	0xFC5A, 0x4C20, 0x0F63, 0x33F9, 0xA764, 0xBF37, 0x8B3F, 0x3449, 
	0xC96E, 0x375C, 0xD66D, 0x18EB, 0xEFBA, 0xDA56, 0x228F, 0x7364, 
	0x0BE8, 0x158A, 0x6620, 0xE86C, 0xD8D9, 0xE800, 0xE3E5, 0x6FA2, 
	0xB0F0, 0x6DA4, 0xAC07, 0x4D85, 0x6ED1, 0x5109, 0xCDA4, 0xFF5F, 
	0x31A1, 0x8F96, 0x8858, 0xD8D2, 0x6559, 0x316C, 0x5800, 0x6669, 
	0x9CBF, 0x7EFA, 0x0643, 0x425F, 0x4CD7, 0x80EB, 0xDE32, 0x93AB, 
	0x9306, 0xC6A5, 0xB67A, 0xA754, 0x46FF, 0xB12D, 0x12C4, 0xF923, 
	0x1FB0, 0x52ED, 0x554C, 0x9DF6, 0xFABB, 0x38BD, 0xFE32, 0x64CA, 
	0x96D7, 0x20D9, 0x095C, 0x358C, 0x48E4, 0xA02D, 0xFA98, 0x45D4, 
	0x5680, 0x8218, 0xC733, 0x8A5E, 0xD8CE, 0xEFFE, 0x7B4B, 0x8B36, 
	0xF255, 0x4FE2, 0x67E9, 0x5763, 0xC72F, 0x129A, 0x19A3, 0x945B, 
	0xC564, 0xDF44, 0xC672, 0xF80E, 0xD40A, 0xFFE1, 0xBEED, 0x87CF, 
	0x4578, 0x5BE4, 0xDED5, 0x5B83, 0x2A0D, 0x7830, 0x16C3, 0x365A, 
	0x6A4B, 0xE1A2, 0x2C0D, 0x70AD, 0xF234, 0xCC8C, 0xC867, 0xF68A, 
}

func GetRandomForHeader() (random uint32) {
	defer func() {
		sbox_counter += 1
		if (sbox_counter >= WG_DEVICE_SBOX_SIZE) {
			sbox_counter = 0
		}
	}()

	return HeaderRandomSBox[sbox_counter]
}
