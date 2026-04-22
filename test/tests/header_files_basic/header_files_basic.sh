#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if dummy modified header files does not generate valid deku module

FILES="drivers/hid/hid-ids.h"
DESCRIPTION="Basic changes in header file"
. test/common.sh

expectedPatches_5_10=(
	patch_0711c614_hid_monterey
	patch_147bf8e3_hid_sunplus
	patch_1eee55b7_hid_petalynx
	patch_2f40cdee_hid_microsoft
	patch_359d05e2_hid_lg_g15
	patch_3a233479_hid_lg4ff
	patch_6874adef_hid_topseed
	patch_7875d817_hid_gyration
	patch_858f5e18_hid_lg
	patch_85afc72e_hid_apple
	patch_931559de_hid_pl
	patch_a1df7423_hid_cherry
	patch_a604ec0f_hid_ite
	patch_a6ec82ed_hid_ntrig
	patch_aa3181c0_hid_samsung
	patch_af7f7356_hid_ezkey
	patch_bd46d4e8_hid_cypress
	patch_bf693bf0_hid_input
	patch_c2c62619_hid_kensington
	patch_ce0ce2c3_hid_quirks
	patch_d2cfff4b_hid_chicony
	patch_d4dd7fa8_hid_core
	patch_d82cd42d_hid_belkin
	patch_d8f8cf00_hid_sony
	patch_e884938c_hid_a4tech
	patch_f3cfb068_hid_redragon
)

expectedPatches_5_15=(
	patch_0711c614_hid_monterey
	patch_147bf8e3_hid_sunplus
	patch_1eee55b7_hid_petalynx
	patch_2f40cdee_hid_microsoft
	patch_359d05e2_hid_lg_g15
	patch_3a233479_hid_lg4ff
	patch_6874adef_hid_topseed
	patch_7875d817_hid_gyration
	patch_858f5e18_hid_lg
	patch_85afc72e_hid_apple
	patch_931559de_hid_pl
	patch_a1df7423_hid_cherry
	patch_a604ec0f_hid_ite
	patch_a6ec82ed_hid_ntrig
	patch_aa3181c0_hid_samsung
	patch_af7f7356_hid_ezkey
	patch_bd46d4e8_hid_cypress
	patch_bf693bf0_hid_input
	patch_c2c62619_hid_kensington
	patch_ce0ce2c3_hid_quirks
	patch_d2cfff4b_hid_chicony
	patch_d4dd7fa8_hid_core
	patch_d82cd42d_hid_belkin
	patch_d8f8cf00_hid_sony
	patch_e884938c_hid_a4tech
	patch_f3cfb068_hid_redragon
)

expectedPatches_6_1=(
	patch_0711c614_hid_monterey
	patch_147bf8e3_hid_sunplus
	patch_1eee55b7_hid_petalynx
	patch_2f40cdee_hid_microsoft
	patch_359d05e2_hid_lg_g15
	patch_3a233479_hid_lg4ff
	patch_6874adef_hid_topseed
	patch_7875d817_hid_gyration
	patch_858f5e18_hid_lg
	patch_85afc72e_hid_apple
	patch_931559de_hid_pl
	patch_a1df7423_hid_cherry
	patch_a604ec0f_hid_ite
	patch_a6ec82ed_hid_ntrig
	patch_aa3181c0_hid_samsung
	patch_af7f7356_hid_ezkey
	patch_bd46d4e8_hid_cypress
	patch_bf693bf0_hid_input
	patch_c2c62619_hid_kensington
	patch_ce0ce2c3_hid_quirks
	patch_d2cfff4b_hid_chicony
	patch_d4dd7fa8_hid_core
	patch_d82cd42d_hid_belkin
	patch_d8f8cf00_hid_sony
	patch_e884938c_hid_a4tech
	patch_f3cfb068_hid_redragon
)

expectedPatches_6_6=(
	patch_0711c614_hid_monterey
	patch_147bf8e3_hid_sunplus
	patch_1eee55b7_hid_petalynx
	patch_2f40cdee_hid_microsoft
	patch_359d05e2_hid_lg_g15
	patch_3a233479_hid_lg4ff
	patch_6874adef_hid_topseed
	patch_7875d817_hid_gyration
	patch_858f5e18_hid_lg
	patch_85afc72e_hid_apple
	patch_931559de_hid_pl
	patch_a1df7423_hid_cherry
	patch_a604ec0f_hid_ite
	patch_a6ec82ed_hid_ntrig
	patch_aa3181c0_hid_samsung
	patch_af7f7356_hid_ezkey
	patch_bd46d4e8_hid_cypress
	patch_bf693bf0_hid_input
	patch_c2c62619_hid_kensington
	patch_ce0ce2c3_hid_quirks
	patch_d2cfff4b_hid_chicony
	patch_d4dd7fa8_hid_core
	patch_d82cd42d_hid_belkin
	patch_d8f8cf00_hid_sony
	patch_e884938c_hid_a4tech
	patch_f3cfb068_hid_redragon
)

expectedPatches_6_12=(
	patch_0711c614_hid_monterey
	patch_147bf8e3_hid_sunplus
	patch_1eee55b7_hid_petalynx
	patch_2f40cdee_hid_microsoft
	patch_359d05e2_hid_lg_g15
	patch_3a233479_hid_lg4ff
	patch_6874adef_hid_topseed
	patch_7875d817_hid_gyration
	patch_858f5e18_hid_lg
	patch_85afc72e_hid_apple
	patch_931559de_hid_pl
	patch_a1df7423_hid_cherry
	patch_a604ec0f_hid_ite
	patch_a6ec82ed_hid_ntrig
	patch_aa3181c0_hid_samsung
	patch_af7f7356_hid_ezkey
	patch_bd46d4e8_hid_cypress
	patch_bf693bf0_hid_input
	patch_c2c62619_hid_kensington
	patch_ce0ce2c3_hid_quirks
	patch_d2cfff4b_hid_chicony
	patch_d4dd7fa8_hid_core
	patch_d82cd42d_hid_belkin
	patch_d8f8cf00_hid_sony
	patch_e884938c_hid_a4tech
	patch_f3cfb068_hid_redragon
)

expectedPatches_6_16=(
	patch_0711c614_hid_monterey
	patch_147bf8e3_hid_sunplus
	patch_1eee55b7_hid_petalynx
	patch_2f40cdee_hid_microsoft
	patch_6874adef_hid_topseed
	patch_7875d817_hid_gyration
	patch_85afc72e_hid_apple
	patch_931559de_hid_pl
	patch_a1df7423_hid_cherry
	patch_a604ec0f_hid_ite
	patch_a6ec82ed_hid_ntrig
	patch_aa3181c0_hid_samsung
	patch_af7f7356_hid_ezkey
	patch_bd46d4e8_hid_cypress
	patch_bf693bf0_hid_input
	patch_c2c62619_hid_kensington
	patch_ce0ce2c3_hid_quirks
	patch_d2cfff4b_hid_chicony
	patch_d4dd7fa8_hid_core
	patch_d82cd42d_hid_belkin
	patch_d8f8cf00_hid_sony
	patch_e884938c_hid_a4tech
	patch_f3cfb068_hid_redragon
)

expectedPatches_cros_5_10=(
	"patch_13ce2b29_hid_generic"
	"patch_2f40cdee_hid_microsoft"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_359d05e2_hid_lg_g15"
	"patch_3f58b910_hid_magicmouse"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_4659d305_hid_primax"
	"patch_567f23f1_hid_plantronics"
	"patch_643ca254_hid_holtek_mouse"
	"patch_65c2c41d_hid_quickstep"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_858f5e18_hid_lg"
	"patch_85afc72e_hid_apple"
	"patch_86e1e138_hid_wiimote_core"
	"patch_878339b2_hid_led"
	"patch_953fabed_hid_rmi"
	"patch_9560d2f9_hid_google_hammer"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_a1df7423_hid_cherry"
	"patch_bf5f5191_hid_multitouch"
	"patch_bf693bf0_hid_input"
	"patch_c2c62619_hid_kensington"
	"patch_cb22b47d_hid_holtekff"
	"patch_ce0ce2c3_hid_quirks"
	"patch_d2cfff4b_hid_chicony"
	"patch_d4dd7fa8_hid_core"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_d8f8cf00_hid_sony"
	"patch_e2cd0e78_hid_jabra"
)

expectedPatches_cros_5_15=(
	"patch_13ce2b29_hid_generic"
	"patch_2f40cdee_hid_microsoft"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_359d05e2_hid_lg_g15"
	"patch_3f58b910_hid_magicmouse"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_4659d305_hid_primax"
	"patch_567f23f1_hid_plantronics"
	"patch_643ca254_hid_holtek_mouse"
	"patch_65c2c41d_hid_quickstep"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_858f5e18_hid_lg"
	"patch_85afc72e_hid_apple"
	"patch_86e1e138_hid_wiimote_core"
	"patch_878339b2_hid_led"
	"patch_953fabed_hid_rmi"
	"patch_9560d2f9_hid_google_hammer"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_a1df7423_hid_cherry"
	"patch_bf5f5191_hid_multitouch"
	"patch_bf693bf0_hid_input"
	"patch_c2c62619_hid_kensington"
	"patch_cb22b47d_hid_holtekff"
	"patch_ce0ce2c3_hid_quirks"
	"patch_d2cfff4b_hid_chicony"
	"patch_d4dd7fa8_hid_core"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_d8f8cf00_hid_sony"
	"patch_e2cd0e78_hid_jabra"
)

expectedPatches_cros_6_1=(
	"patch_13ce2b29_hid_generic"
	"patch_2f40cdee_hid_microsoft"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_359d05e2_hid_lg_g15"
	"patch_3f58b910_hid_magicmouse"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_4659d305_hid_primax"
	"patch_567f23f1_hid_plantronics"
	"patch_643ca254_hid_holtek_mouse"
	"patch_65c2c41d_hid_quickstep"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_858f5e18_hid_lg"
	"patch_85afc72e_hid_apple"
	"patch_86e1e138_hid_wiimote_core"
	"patch_878339b2_hid_led"
	"patch_953fabed_hid_rmi"
	"patch_9560d2f9_hid_google_hammer"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_a1df7423_hid_cherry"
	"patch_bf5f5191_hid_multitouch"
	"patch_bf693bf0_hid_input"
	"patch_c2c62619_hid_kensington"
	"patch_cb22b47d_hid_holtekff"
	"patch_ce0ce2c3_hid_quirks"
	"patch_d2cfff4b_hid_chicony"
	"patch_d4dd7fa8_hid_core"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_d8f8cf00_hid_sony"
	"patch_e2cd0e78_hid_jabra"
)

expectedPatches_cros_6_6=(
	"patch_2f40cdee_hid_microsoft"
	"patch_3f58b910_hid_magicmouse"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_13ce2b29_hid_generic"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_65c2c41d_hid_quickstep"
	"patch_85afc72e_hid_apple"
	"patch_86e1e138_hid_wiimote_core"
	"patch_359d05e2_hid_lg_g15"
	"patch_567f23f1_hid_plantronics"
	"patch_643ca254_hid_holtek_mouse"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_858f5e18_hid_lg"
	"patch_953fabed_hid_rmi"
	"patch_4659d305_hid_primax"
	"patch_9560d2f9_hid_google_hammer"
	"patch_878339b2_hid_led"
	"patch_a1df7423_hid_cherry"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_bf5f5191_hid_multitouch"
	"patch_bf693bf0_hid_input"
	"patch_c2c62619_hid_kensington"
	"patch_cb22b47d_hid_holtekff"
	"patch_ce0ce2c3_hid_quirks"
	"patch_d2cfff4b_hid_chicony"
	"patch_d4dd7fa8_hid_core"
	"patch_d8f8cf00_hid_sony"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_e2cd0e78_hid_jabra"
)

expectedPatches_cros_6_12=(
	"patch_2f40cdee_hid_microsoft"
	"patch_3f58b910_hid_magicmouse"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_13ce2b29_hid_generic"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_65c2c41d_hid_quickstep"
	"patch_85afc72e_hid_apple"
	"patch_86e1e138_hid_wiimote_core"
	"patch_359d05e2_hid_lg_g15"
	"patch_567f23f1_hid_plantronics"
	"patch_643ca254_hid_holtek_mouse"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_858f5e18_hid_lg"
	"patch_953fabed_hid_rmi"
	"patch_4659d305_hid_primax"
	"patch_9560d2f9_hid_google_hammer"
	"patch_878339b2_hid_led"
	"patch_a1df7423_hid_cherry"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_bf5f5191_hid_multitouch"
	"patch_bf693bf0_hid_input"
	"patch_c2c62619_hid_kensington"
	"patch_cb22b47d_hid_holtekff"
	"patch_ce0ce2c3_hid_quirks"
	"patch_d2cfff4b_hid_chicony"
	"patch_d4dd7fa8_hid_core"
	"patch_d8f8cf00_hid_sony"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_e2cd0e78_hid_jabra"
)

expectedPatches_ubuntu_6_8=(
	"patch_015373ec_hid_macally"
	"patch_4e857db3_hid_roccat_koneplus"
	"patch_a6096f3b_hid_roccat_konepure"
	"patch_025c09a4_hid_prodikeys"
	"patch_516a4aca_hid_megaworld"
	"patch_a6ec82ed_hid_ntrig"
	"patch_0711c614_hid_monterey"
	"patch_53b62740_hid_u2fzero"
	"patch_a8a42715_hid_sjoy"
	"patch_0bddf1f5_hid_elan"
	"patch_567f23f1_hid_plantronics"
	"patch_aa3181c0_hid_samsung"
	"patch_0e5829ae_hid_cp2112"
	"patch_5ad6176c_hid_dr"
	"patch_aa446184_hid_gembird"
	"patch_1383328a_hid_picolcd_leds"
	"patch_5e5c8109_hid_lcpower"
	"patch_ab366fa1_hid_icade"
	"patch_147bf8e3_hid_sunplus"
	"patch_61b12ec8_usbmouse"
	"patch_af7f7356_hid_ezkey"
	"patch_151384bf_hid_udraw_ps3"
	"patch_62122d38_hid_saitek"
	"patch_b1b8af5f_hid_roccat_pyra"
	"patch_15286137_hid_uclogic_core"
	"patch_643ca254_hid_holtek_mouse"
	"patch_b979435b_hid_asus"
	"patch_1594733e_hid_roccat_kovaplus"
	"patch_6874adef_hid_topseed"
	"patch_ba069948_hid_steam"
	"patch_19127e53_hid_zydacron"
	"patch_6c17b33a_hid_alps"
	"patch_bd46d4e8_hid_cypress"
	"patch_1a4ed938_hid_ortek"
	"patch_6df3607a_hid_tmff"
	"patch_bf5f5191_hid_multitouch"
	"patch_1d3ec97b_hid_nti"
	"patch_6f4df912_hid_semitek"
	"patch_bf693bf0_hid_input"
	"patch_1eee55b7_hid_petalynx"
	"patch_700ca3d5_hid_maltron"
	"patch_c001e5f0_hid_google_stadiaff"
	"patch_1f040f5d_hid_betopff"
	"patch_71a16e0b_hid_aureal"
	"patch_c26b6d12_hid_keytouch"
	"patch_21c2e928_hid_accutouch"
	"patch_7723636b_hid_elecom"
	"patch_c2c62619_hid_kensington"
	"patch_2acf7fde_hid_roccat_kone"
	"patch_7875d817_hid_gyration"
	"patch_c5bc4f7f_hid_picolcd_core"
	"patch_2d41fd4e_hid_gaff"
	"patch_7c56ec2a_hid_lenovo"
	"patch_c7bbaaaa_hid_tivo"
	"patch_2eae67b2_hid_kye"
	"patch_7e4b74eb_hid_penmount"
	"patch_c95b1e84_hid_waltop"
	"patch_2f40cdee_hid_microsoft"
	"patch_81574754_hid_cougar"
	"patch_cb22b47d_hid_holtekff"
	"patch_316d41c6_hid_viewsonic"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_ce0ce2c3_hid_quirks"
	"patch_31c4a776_hid_xiaomi"
	"patch_858f5e18_hid_lg"
	"patch_cf895239_hid_zpff"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_85afc72e_hid_apple"
	"patch_d2cfff4b_hid_chicony"
	"patch_3206bd8b_hid_roccat_lua"
	"patch_86e1e138_hid_wiimote_core"
	"patch_d4dd7fa8_hid_core"
	"patch_324f666b_hid_gt683r"
	"patch_87257ecd_hid_steelseries"
	"patch_d82cd42d_hid_belkin"
	"patch_34f81ebd_hid_glorious"
	"patch_878339b2_hid_led"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_35104aff_hid_creative_sb0540"
	"patch_87d238bd_hid_pxrc"
	"patch_d8f8cf00_hid_sony"
	"patch_359d05e2_hid_lg_g15"
	"patch_896a1bf0_hid_cmedia"
	"patch_e2cd0e78_hid_jabra"
	"patch_35c2729d_hid_razer"
	"patch_8b1ef52d_hid_roccat_arvo"
	"patch_e4eb14a6_hid_letsketch"
	"patch_376db302_hid_ft260"
	"patch_8b455962_hid_appleir"
	"patch_e4f3d695_hid_emsff"
	"patch_379545c2_hid_picolcd_cir"
	"patch_90b755c4_hid_corsair"
	"patch_e5a78073_hid_evision"
	"patch_39cb8630_hid_xinmo"
	"patch_931559de_hid_pl"
	"patch_e6e9ff64_hid_mcp2200"
	"patch_3a233479_hid_lg4ff"
	"patch_93ae5f30_hid_sensor_hub"
	"patch_e884938c_hid_a4tech"
	"patch_3cf1534a_hid_mf"
	"patch_953fabed_hid_rmi"
	"patch_e9eff714_hid_roccat_isku"
	"patch_3e9e67ec_hid_bigbenff"
	"patch_9560d2f9_hid_google_hammer"
	"patch_f0419919_hid_twinhan"
	"patch_3f58b910_hid_magicmouse"
	"patch_96e8eba0_hid_axff"
	"patch_f20fe4a5_hid_topre"
	"patch_41a1f608_hid_roccat_ryos"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_f3a9534a_hid_sigmamicro"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_9d590815_hid_playstation"
	"patch_f3cfb068_hid_redragon"
	"patch_4659d305_hid_primax"
	"patch_a016140f_hid_speedlink"
	"patch_f3f19d49_hid_roccat_savu"
	"patch_46732ae8_hid_retrode"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_f6db7015_hid_uclogic_params"
	"patch_4c4f0e77_hid_gfrm"
	"patch_a1df7423_hid_cherry"
	"patch_fbcefba8_hid_elo"
	"patch_4d225dd8_hid_mcp2221"
	"patch_a604ec0f_hid_ite"
	"patch_fe3af69e_hid_nvidia_shield"
)

expectedPatches_ubuntu_6_14=(
	"patch_015373ec_hid_macally"
	"patch_4e857db3_hid_roccat_koneplus"
	"patch_a6096f3b_hid_roccat_konepure"
	"patch_025c09a4_hid_prodikeys"
	"patch_516a4aca_hid_megaworld"
	"patch_a6ec82ed_hid_ntrig"
	"patch_0711c614_hid_monterey"
	"patch_53b62740_hid_u2fzero"
	"patch_a8a42715_hid_sjoy"
	"patch_0bddf1f5_hid_elan"
	"patch_567f23f1_hid_plantronics"
	"patch_aa3181c0_hid_samsung"
	"patch_0e5829ae_hid_cp2112"
	"patch_5ad6176c_hid_dr"
	"patch_aa446184_hid_gembird"
	"patch_1383328a_hid_picolcd_leds"
	"patch_5e5c8109_hid_lcpower"
	"patch_ab366fa1_hid_icade"
	"patch_147bf8e3_hid_sunplus"
	"patch_61b12ec8_usbmouse"
	"patch_af7f7356_hid_ezkey"
	"patch_151384bf_hid_udraw_ps3"
	"patch_62122d38_hid_saitek"
	"patch_b1b8af5f_hid_roccat_pyra"
	"patch_15286137_hid_uclogic_core"
	"patch_643ca254_hid_holtek_mouse"
	"patch_b979435b_hid_asus"
	"patch_1594733e_hid_roccat_kovaplus"
	"patch_6874adef_hid_topseed"
	"patch_ba069948_hid_steam"
	"patch_19127e53_hid_zydacron"
	"patch_6c17b33a_hid_alps"
	"patch_bd46d4e8_hid_cypress"
	"patch_1a4ed938_hid_ortek"
	"patch_6df3607a_hid_tmff"
	"patch_bf5f5191_hid_multitouch"
	"patch_1d3ec97b_hid_nti"
	"patch_6f4df912_hid_semitek"
	"patch_bf693bf0_hid_input"
	"patch_1eee55b7_hid_petalynx"
	"patch_700ca3d5_hid_maltron"
	"patch_c001e5f0_hid_google_stadiaff"
	"patch_1f040f5d_hid_betopff"
	"patch_71a16e0b_hid_aureal"
	"patch_c26b6d12_hid_keytouch"
	"patch_21c2e928_hid_accutouch"
	"patch_7723636b_hid_elecom"
	"patch_c2c62619_hid_kensington"
	"patch_2acf7fde_hid_roccat_kone"
	"patch_7875d817_hid_gyration"
	"patch_c5bc4f7f_hid_picolcd_core"
	"patch_2d41fd4e_hid_gaff"
	"patch_7c56ec2a_hid_lenovo"
	"patch_c7bbaaaa_hid_tivo"
	"patch_2eae67b2_hid_kye"
	"patch_7e4b74eb_hid_penmount"
	"patch_c95b1e84_hid_waltop"
	"patch_2f40cdee_hid_microsoft"
	"patch_81574754_hid_cougar"
	"patch_cb22b47d_hid_holtekff"
	"patch_316d41c6_hid_viewsonic"
	"patch_817a5f23_hid_holtek_kbd"
	"patch_ce0ce2c3_hid_quirks"
	"patch_31c4a776_hid_xiaomi"
	"patch_858f5e18_hid_lg"
	"patch_cf895239_hid_zpff"
	"patch_31d6ba2d_i2c_hid_core"
	"patch_85afc72e_hid_apple"
	"patch_d2cfff4b_hid_chicony"
	"patch_3206bd8b_hid_roccat_lua"
	"patch_86e1e138_hid_wiimote_core"
	"patch_d4dd7fa8_hid_core"
	"patch_324f666b_hid_gt683r"
	"patch_87257ecd_hid_steelseries"
	"patch_d82cd42d_hid_belkin"
	"patch_34f81ebd_hid_glorious"
	"patch_878339b2_hid_led"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_35104aff_hid_creative_sb0540"
	"patch_87d238bd_hid_pxrc"
	"patch_d8f8cf00_hid_sony"
	"patch_359d05e2_hid_lg_g15"
	"patch_896a1bf0_hid_cmedia"
	"patch_e2cd0e78_hid_jabra"
	"patch_35c2729d_hid_razer"
	"patch_8b1ef52d_hid_roccat_arvo"
	"patch_e4eb14a6_hid_letsketch"
	"patch_376db302_hid_ft260"
	"patch_8b455962_hid_appleir"
	"patch_e4f3d695_hid_emsff"
	"patch_379545c2_hid_picolcd_cir"
	"patch_90b755c4_hid_corsair"
	"patch_e5a78073_hid_evision"
	"patch_39cb8630_hid_xinmo"
	"patch_931559de_hid_pl"
	"patch_e6e9ff64_hid_mcp2200"
	"patch_3a233479_hid_lg4ff"
	"patch_93ae5f30_hid_sensor_hub"
	"patch_e884938c_hid_a4tech"
	"patch_3cf1534a_hid_mf"
	"patch_953fabed_hid_rmi"
	"patch_e9eff714_hid_roccat_isku"
	"patch_3e9e67ec_hid_bigbenff"
	"patch_9560d2f9_hid_google_hammer"
	"patch_f0419919_hid_twinhan"
	"patch_3f58b910_hid_magicmouse"
	"patch_96e8eba0_hid_axff"
	"patch_f20fe4a5_hid_topre"
	"patch_41a1f608_hid_roccat_ryos"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_f3a9534a_hid_sigmamicro"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_9d590815_hid_playstation"
	"patch_f3cfb068_hid_redragon"
	"patch_4659d305_hid_primax"
	"patch_a016140f_hid_speedlink"
	"patch_f3f19d49_hid_roccat_savu"
	"patch_46732ae8_hid_retrode"
	"patch_a12c7f34_i2c_hid_dmi_quirks"
	"patch_f6db7015_hid_uclogic_params"
	"patch_4c4f0e77_hid_gfrm"
	"patch_a1df7423_hid_cherry"
	"patch_fbcefba8_hid_elo"
	"patch_4d225dd8_hid_mcp2221"
	"patch_a604ec0f_hid_ite"
	"patch_fe3af69e_hid_nvidia_shield"
	"patch_38e9af8b_hid_corsair_void"
)

expectedPatches_android_6_12=(
	"patch_025c09a4_hid_prodikeys"
	"patch_15286137_hid_uclogic_core"
	"patch_1594733e_hid_roccat_kovaplus"
	"patch_2acf7fde_hid_roccat_kone"
	"patch_2f40cdee_hid_microsoft"
	"patch_3206bd8b_hid_roccat_lua"
	"patch_359d05e2_hid_lg_g15"
	"patch_3f58b910_hid_magicmouse"
	"patch_41a1f608_hid_roccat_ryos"
	"patch_41e1d08e_hid_logitech_dj"
	"patch_4e857db3_hid_roccat_koneplus"
	"patch_567f23f1_hid_plantronics"
	"patch_7723636b_hid_elecom"
	"patch_858f5e18_hid_lg"
	"patch_85afc72e_hid_apple"
	"patch_86e1e138_hid_wiimote_core"
	"patch_8b1ef52d_hid_roccat_arvo"
	"patch_9a3bc6b9_hid_nintendo"
	"patch_9d590815_hid_playstation"
	"patch_a6096f3b_hid_roccat_konepure"
	"patch_b1b8af5f_hid_roccat_pyra"
	"patch_ba069948_hid_steam"
	"patch_bf5f5191_hid_multitouch"
	"patch_bf693bf0_hid_input"
	"patch_c5bc4f7f_hid_picolcd_core"
	"patch_ce0ce2c3_hid_quirks"
	"patch_d4dd7fa8_hid_core"
	"patch_d84909f5_hid_logitech_hidpp"
	"patch_d8f8cf00_hid_sony"
	"patch_e9eff714_hid_roccat_isku"
	"patch_f3f19d49_hid_roccat_savu"
	"patch_f6db7015_hid_uclogic_params"
)

test()
{
	local srcDir=$SOURCE_DIR

	local expectedPatches=

	if [[ $ANDROID ]]; then
		expectedPatches="${expectedPatches_android_6_12[@]}"

	elif [[ "$KERNEL_VER" == "v5.10" ]]; then
		expectedPatches="${expectedPatches_cros_5_10[@]}"
	elif [[ "$KERNEL_VER" == "v5.15" ]]; then
		expectedPatches="${expectedPatches_cros_5_15[@]}"
	elif [[ "$KERNEL_VER" == "v6.1" ]]; then
		expectedPatches="${expectedPatches_cros_6_1[@]}"
	elif [[ "$KERNEL_VER" == "v6.6" ]]; then
		expectedPatches="${expectedPatches_cros_6_6[@]}"
	elif [[ "$KERNEL_VER" == "v6.12" ]]; then
		expectedPatches="${expectedPatches_cros_6_12[@]}"

	elif [[ "$KERNEL_VERSION" == "v5.10."* ]]; then
		expectedPatches="${expectedPatches_5_10[@]}"
	elif [[ "$KERNEL_VERSION" == "v5.15."* ]]; then
		expectedPatches="${expectedPatches_5_15[@]}"
	elif [[ "$KERNEL_VERSION" == "v6.1."* ]]; then
		expectedPatches="${expectedPatches_6_1[@]}"
	elif [[ "$KERNEL_VERSION" == "v6.6."* ]]; then
		expectedPatches="${expectedPatches_6_6[@]}"
	elif [[ "$KERNEL_VERSION" == "v6.12."* ]]; then
		expectedPatches="${expectedPatches_6_12[@]}"
	elif [[ "$KERNEL_VERSION" == "v6.16-"* ]]; then
		expectedPatches="${expectedPatches_6_16[@]}"

	elif [[ "$KERNEL_VER" == "v6.8" ]]; then
		expectedPatches="${expectedPatches_ubuntu_6_8[@]}"
	elif [[ "$KERNEL_VER" == "v6.11" ]]; then
		expectedPatches="${expectedPatches_ubuntu_6_8[@]}"
	elif [[ "$KERNEL_VER" == "v6.14" ]]; then
		expectedPatches="${expectedPatches_ubuntu_6_14[@]}"
	fi

	if [[ "$expectedPatches" == "" ]]; then
		logErr "Can't find pattern for: $KERNEL_VER"
		exitError 1;
	fi

	# start from fresh sources and kernel
	prepareKernelAndDeploy $KERNEL_VER || exitError 2;
	touch "$BUILD_DIR/vmlinux"
	touch "$BUILD_DIR/Makefile"

	echo "" >> "$srcDir/drivers/hid/hid-ids.h"

	logStep -n "Check if changes in .h detects proper source files..."
	out=$(dekuBuild --stdout -v)
	local res=$?
	[[ $res != 0 ]] && { echo "$out"; exitError 3; }

	grep -q "No valid changes detected" <<< "$out" || { echo "$out"; echo "Fail"; exitError 4; }

	local patches=$(find $WORKDIR -type d -name "patch_*" -printf "%f\n" | sort)
	echo "$patches" >> $LOG_FILE
	local result=$(echo ${expectedPatches[@]} "$patches" | tr ' ' '\n' | sort | uniq -u)
	[[ $result != "" ]] && { logErr "Workdir contains unexpected patches: $result"; exitError 5; }
	workdirContainsOnly || exitError $LINENO
	logStep "OK"

	logStep -n "Check if changes in .h file are properly handled..."
	out=$(dekuBuild --stdout -v)
	res=$?
	[[ $res != 0 ]] && { echo "$out"; exitError 6; }
	grep -q "No valid changes detected" <<< "$out" || { echo "$out"; echo "Fail"; exitError 7; }
	workdirContainsOnly || exitError $LINENO
	logStep "$KERNEL_VER... OK"
}

main()
{
	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
