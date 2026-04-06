--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: syslog
version: 2
description: A standard for logging program messages.
bundle_description: $VAR1 = {
          'syslog' => 'A standard for logging program messages.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "syslog",
    proto =  DC.ipproto.udp, --should be both?
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdSyslog = 462

gPatterns = {
    facpri0 = {"<0>", 0, gSfAppIdSyslog},
    facpri1 = {"<1>", 0, gSfAppIdSyslog},
    facpri2 = {"<2>", 0, gSfAppIdSyslog},
    facpri3 = {"<3>", 0, gSfAppIdSyslog},
    facpri4 = {"<4>", 0, gSfAppIdSyslog},
    facpri5 = {"<5>", 0, gSfAppIdSyslog},
    facpri6 = {"<6>", 0, gSfAppIdSyslog},
    facpri7 = {"<7>", 0, gSfAppIdSyslog},
    facpri8 = {"<8>", 0, gSfAppIdSyslog},
    facpri9 = {"<9>", 0, gSfAppIdSyslog},
    facpri10 = {"<10>", 0, gSfAppIdSyslog},
    facpri11 = {"<11>", 0, gSfAppIdSyslog},
    facpri12 = {"<12>", 0, gSfAppIdSyslog},
    facpri13 = {"<13>", 0, gSfAppIdSyslog},
    facpri14 = {"<14>", 0, gSfAppIdSyslog},
    facpri15 = {"<15>", 0, gSfAppIdSyslog},
    facpri16 = {"<16>", 0, gSfAppIdSyslog},
    facpri17 = {"<17>", 0, gSfAppIdSyslog},
    facpri18 = {"<18>", 0, gSfAppIdSyslog},
    facpri19 = {"<19>", 0, gSfAppIdSyslog},
    facpri20 = {"<20>", 0, gSfAppIdSyslog},
    facpri21 = {"<21>", 0, gSfAppIdSyslog},
    facpri22 = {"<22>", 0, gSfAppIdSyslog},
    facpri23 = {"<23>", 0, gSfAppIdSyslog},
    facpri24 = {"<24>", 0, gSfAppIdSyslog},
    facpri25 = {"<25>", 0, gSfAppIdSyslog},
    facpri26 = {"<26>", 0, gSfAppIdSyslog},
    facpri27 = {"<27>", 0, gSfAppIdSyslog},
    facpri28 = {"<28>", 0, gSfAppIdSyslog},
    facpri29 = {"<29>", 0, gSfAppIdSyslog},
    facpri30 = {"<30>", 0, gSfAppIdSyslog},
    facpri31 = {"<31>", 0, gSfAppIdSyslog},
    facpri32 = {"<32>", 0, gSfAppIdSyslog},
    facpri33 = {"<33>", 0, gSfAppIdSyslog},
    facpri34 = {"<34>", 0, gSfAppIdSyslog},
    facpri35 = {"<35>", 0, gSfAppIdSyslog},
    facpri36 = {"<36>", 0, gSfAppIdSyslog},
    facpri37 = {"<37>", 0, gSfAppIdSyslog},
    facpri38 = {"<38>", 0, gSfAppIdSyslog},
    facpri39 = {"<39>", 0, gSfAppIdSyslog},
    facpri40 = {"<40>", 0, gSfAppIdSyslog},
    facpri41 = {"<41>", 0, gSfAppIdSyslog},
    facpri42 = {"<42>", 0, gSfAppIdSyslog},
    facpri43 = {"<43>", 0, gSfAppIdSyslog},
    facpri44 = {"<44>", 0, gSfAppIdSyslog},
    facpri45 = {"<45>", 0, gSfAppIdSyslog},
    facpri46 = {"<46>", 0, gSfAppIdSyslog},
    facpri47 = {"<47>", 0, gSfAppIdSyslog},
    facpri48 = {"<48>", 0, gSfAppIdSyslog},
    facpri49 = {"<49>", 0, gSfAppIdSyslog},
    facpri50 = {"<50>", 0, gSfAppIdSyslog},
    facpri51 = {"<51>", 0, gSfAppIdSyslog},
    facpri52 = {"<52>", 0, gSfAppIdSyslog},
    facpri53 = {"<53>", 0, gSfAppIdSyslog},
    facpri54 = {"<54>", 0, gSfAppIdSyslog},
    facpri55 = {"<55>", 0, gSfAppIdSyslog},
    facpri56 = {"<56>", 0, gSfAppIdSyslog},
    facpri57 = {"<57>", 0, gSfAppIdSyslog},
    facpri58 = {"<58>", 0, gSfAppIdSyslog},
    facpri59 = {"<59>", 0, gSfAppIdSyslog},
    facpri60 = {"<60>", 0, gSfAppIdSyslog},
    facpri61 = {"<61>", 0, gSfAppIdSyslog},
    facpri62 = {"<62>", 0, gSfAppIdSyslog},
    facpri63 = {"<63>", 0, gSfAppIdSyslog},
    facpri64 = {"<64>", 0, gSfAppIdSyslog},
    facpri65 = {"<65>", 0, gSfAppIdSyslog},
    facpri66 = {"<66>", 0, gSfAppIdSyslog},
    facpri67 = {"<67>", 0, gSfAppIdSyslog},
    facpri68 = {"<68>", 0, gSfAppIdSyslog},
    facpri69 = {"<69>", 0, gSfAppIdSyslog},
    facpri70 = {"<70>", 0, gSfAppIdSyslog},
    facpri71 = {"<71>", 0, gSfAppIdSyslog},
    facpri72 = {"<72>", 0, gSfAppIdSyslog},
    facpri73 = {"<73>", 0, gSfAppIdSyslog},
    facpri74 = {"<74>", 0, gSfAppIdSyslog},
    facpri75 = {"<75>", 0, gSfAppIdSyslog},
    facpri76 = {"<76>", 0, gSfAppIdSyslog},
    facpri77 = {"<77>", 0, gSfAppIdSyslog},
    facpri78 = {"<78>", 0, gSfAppIdSyslog},
    facpri79 = {"<79>", 0, gSfAppIdSyslog},
    facpri80 = {"<80>", 0, gSfAppIdSyslog},
    facpri81 = {"<81>", 0, gSfAppIdSyslog},
    facpri82 = {"<82>", 0, gSfAppIdSyslog},
    facpri83 = {"<83>", 0, gSfAppIdSyslog},
    facpri84 = {"<84>", 0, gSfAppIdSyslog},
    facpri85 = {"<85>", 0, gSfAppIdSyslog},
    facpri86 = {"<86>", 0, gSfAppIdSyslog},
    facpri87 = {"<87>", 0, gSfAppIdSyslog},
    facpri88 = {"<88>", 0, gSfAppIdSyslog},
    facpri89 = {"<89>", 0, gSfAppIdSyslog},
    facpri90 = {"<90>", 0, gSfAppIdSyslog},
    facpri91 = {"<91>", 0, gSfAppIdSyslog},
    facpri92 = {"<92>", 0, gSfAppIdSyslog},
    facpri93 = {"<93>", 0, gSfAppIdSyslog},
    facpri94 = {"<94>", 0, gSfAppIdSyslog},
    facpri95 = {"<95>", 0, gSfAppIdSyslog},
    facpri96 = {"<96>", 0, gSfAppIdSyslog},
    facpri97 = {"<97>", 0, gSfAppIdSyslog},
    facpri98 = {"<98>", 0, gSfAppIdSyslog},
    facpri99 = {"<99>", 0, gSfAppIdSyslog},
    facpri100 = {"<100>", 0, gSfAppIdSyslog},
    facpri101 = {"<101>", 0, gSfAppIdSyslog},
    facpri102 = {"<102>", 0, gSfAppIdSyslog},
    facpri103 = {"<103>", 0, gSfAppIdSyslog},
    facpri104 = {"<104>", 0, gSfAppIdSyslog},
    facpri105 = {"<105>", 0, gSfAppIdSyslog},
    facpri106 = {"<106>", 0, gSfAppIdSyslog},
    facpri107 = {"<107>", 0, gSfAppIdSyslog},
    facpri108 = {"<108>", 0, gSfAppIdSyslog},
    facpri109 = {"<109>", 0, gSfAppIdSyslog},
    facpri110 = {"<110>", 0, gSfAppIdSyslog},
    facpri111 = {"<111>", 0, gSfAppIdSyslog},
    facpri112 = {"<112>", 0, gSfAppIdSyslog},
    facpri113 = {"<113>", 0, gSfAppIdSyslog},
    facpri114 = {"<114>", 0, gSfAppIdSyslog},
    facpri115 = {"<115>", 0, gSfAppIdSyslog},
    facpri116 = {"<116>", 0, gSfAppIdSyslog},
    facpri117 = {"<117>", 0, gSfAppIdSyslog},
    facpri118 = {"<118>", 0, gSfAppIdSyslog},
    facpri119 = {"<119>", 0, gSfAppIdSyslog},
    facpri120 = {"<120>", 0, gSfAppIdSyslog},
    facpri121 = {"<121>", 0, gSfAppIdSyslog},
    facpri122 = {"<122>", 0, gSfAppIdSyslog},
    facpri123 = {"<123>", 0, gSfAppIdSyslog},
    facpri124 = {"<124>", 0, gSfAppIdSyslog},
    facpri125 = {"<125>", 0, gSfAppIdSyslog},
    facpri126 = {"<126>", 0, gSfAppIdSyslog},
    facpri127 = {"<127>", 0, gSfAppIdSyslog},
    facpri128 = {"<128>", 0, gSfAppIdSyslog},
    facpri129 = {"<129>", 0, gSfAppIdSyslog},
    facpri130 = {"<130>", 0, gSfAppIdSyslog},
    facpri131 = {"<131>", 0, gSfAppIdSyslog},
    facpri132 = {"<132>", 0, gSfAppIdSyslog},
    facpri133 = {"<133>", 0, gSfAppIdSyslog},
    facpri134 = {"<134>", 0, gSfAppIdSyslog},
    facpri135 = {"<135>", 0, gSfAppIdSyslog},
    facpri136 = {"<136>", 0, gSfAppIdSyslog},
    facpri137 = {"<137>", 0, gSfAppIdSyslog},
    facpri138 = {"<138>", 0, gSfAppIdSyslog},
    facpri139 = {"<139>", 0, gSfAppIdSyslog},
    facpri140 = {"<140>", 0, gSfAppIdSyslog},
    facpri141 = {"<141>", 0, gSfAppIdSyslog},
    facpri142 = {"<142>", 0, gSfAppIdSyslog},
    facpri143 = {"<143>", 0, gSfAppIdSyslog},
    facpri144 = {"<144>", 0, gSfAppIdSyslog},
    facpri145 = {"<145>", 0, gSfAppIdSyslog},
    facpri146 = {"<146>", 0, gSfAppIdSyslog},
    facpri147 = {"<147>", 0, gSfAppIdSyslog},
    facpri148 = {"<148>", 0, gSfAppIdSyslog},
    facpri149 = {"<149>", 0, gSfAppIdSyslog},
    facpri150 = {"<150>", 0, gSfAppIdSyslog},
    facpri151 = {"<151>", 0, gSfAppIdSyslog},
    facpri152 = {"<152>", 0, gSfAppIdSyslog},
    facpri153 = {"<153>", 0, gSfAppIdSyslog},
    facpri154 = {"<154>", 0, gSfAppIdSyslog},
    facpri155 = {"<155>", 0, gSfAppIdSyslog},
    facpri156 = {"<156>", 0, gSfAppIdSyslog},
    facpri157 = {"<157>", 0, gSfAppIdSyslog},
    facpri158 = {"<158>", 0, gSfAppIdSyslog},
    facpri159 = {"<159>", 0, gSfAppIdSyslog},
    facpri160 = {"<160>", 0, gSfAppIdSyslog},
    facpri161 = {"<161>", 0, gSfAppIdSyslog},
    facpri162 = {"<162>", 0, gSfAppIdSyslog},
    facpri163 = {"<163>", 0, gSfAppIdSyslog},
    facpri164 = {"<164>", 0, gSfAppIdSyslog},
    facpri165 = {"<165>", 0, gSfAppIdSyslog},
    facpri166 = {"<166>", 0, gSfAppIdSyslog},
    facpri167 = {"<167>", 0, gSfAppIdSyslog},
    facpri168 = {"<168>", 0, gSfAppIdSyslog},
    facpri169 = {"<169>", 0, gSfAppIdSyslog},
    facpri170 = {"<170>", 0, gSfAppIdSyslog},
    facpri171 = {"<171>", 0, gSfAppIdSyslog},
    facpri172 = {"<172>", 0, gSfAppIdSyslog},
    facpri173 = {"<173>", 0, gSfAppIdSyslog},
    facpri174 = {"<174>", 0, gSfAppIdSyslog},
    facpri175 = {"<175>", 0, gSfAppIdSyslog},
    facpri176 = {"<176>", 0, gSfAppIdSyslog},
    facpri177 = {"<177>", 0, gSfAppIdSyslog},
    facpri178 = {"<178>", 0, gSfAppIdSyslog},
    facpri179 = {"<179>", 0, gSfAppIdSyslog},
    facpri180 = {"<180>", 0, gSfAppIdSyslog},
    facpri181 = {"<181>", 0, gSfAppIdSyslog},
    facpri182 = {"<182>", 0, gSfAppIdSyslog},
    facpri183 = {"<183>", 0, gSfAppIdSyslog},
    facpri184 = {"<184>", 0, gSfAppIdSyslog},
    facpri185 = {"<185>", 0, gSfAppIdSyslog},
    facpri186 = {"<186>", 0, gSfAppIdSyslog},
    facpri187 = {"<187>", 0, gSfAppIdSyslog},
    facpri188 = {"<188>", 0, gSfAppIdSyslog},
    facpri189 = {"<189>", 0, gSfAppIdSyslog},
    facpri190 = {"<190>", 0, gSfAppIdSyslog},
    facpri191 = {"<191>", 0, gSfAppIdSyslog},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.facpri0},
    {DC.ipproto.udp, gPatterns.facpri1},
    {DC.ipproto.udp, gPatterns.facpri2},
    {DC.ipproto.udp, gPatterns.facpri3},
    {DC.ipproto.udp, gPatterns.facpri4},
    {DC.ipproto.udp, gPatterns.facpri5},
    {DC.ipproto.udp, gPatterns.facpri6},
    {DC.ipproto.udp, gPatterns.facpri7},
    {DC.ipproto.udp, gPatterns.facpri8},
    {DC.ipproto.udp, gPatterns.facpri9},
    {DC.ipproto.udp, gPatterns.facpri10},
    {DC.ipproto.udp, gPatterns.facpri11},
    {DC.ipproto.udp, gPatterns.facpri12},
    {DC.ipproto.udp, gPatterns.facpri13},
    {DC.ipproto.udp, gPatterns.facpri14},
    {DC.ipproto.udp, gPatterns.facpri15},
    {DC.ipproto.udp, gPatterns.facpri16},
    {DC.ipproto.udp, gPatterns.facpri17},
    {DC.ipproto.udp, gPatterns.facpri18},
    {DC.ipproto.udp, gPatterns.facpri19},
    {DC.ipproto.udp, gPatterns.facpri20},
    {DC.ipproto.udp, gPatterns.facpri21},
    {DC.ipproto.udp, gPatterns.facpri22},
    {DC.ipproto.udp, gPatterns.facpri23},
    {DC.ipproto.udp, gPatterns.facpri24},
    {DC.ipproto.udp, gPatterns.facpri25},
    {DC.ipproto.udp, gPatterns.facpri26},
    {DC.ipproto.udp, gPatterns.facpri27},
    {DC.ipproto.udp, gPatterns.facpri28},
    {DC.ipproto.udp, gPatterns.facpri29},
    {DC.ipproto.udp, gPatterns.facpri30},
    {DC.ipproto.udp, gPatterns.facpri31},
    {DC.ipproto.udp, gPatterns.facpri32},
    {DC.ipproto.udp, gPatterns.facpri33},
    {DC.ipproto.udp, gPatterns.facpri34},
    {DC.ipproto.udp, gPatterns.facpri35},
    {DC.ipproto.udp, gPatterns.facpri36},
    {DC.ipproto.udp, gPatterns.facpri37},
    {DC.ipproto.udp, gPatterns.facpri38},
    {DC.ipproto.udp, gPatterns.facpri39},
    {DC.ipproto.udp, gPatterns.facpri40},
    {DC.ipproto.udp, gPatterns.facpri41},
    {DC.ipproto.udp, gPatterns.facpri42},
    {DC.ipproto.udp, gPatterns.facpri43},
    {DC.ipproto.udp, gPatterns.facpri44},
    {DC.ipproto.udp, gPatterns.facpri45},
    {DC.ipproto.udp, gPatterns.facpri46},
    {DC.ipproto.udp, gPatterns.facpri47},
    {DC.ipproto.udp, gPatterns.facpri48},
    {DC.ipproto.udp, gPatterns.facpri49},
    {DC.ipproto.udp, gPatterns.facpri50},
    {DC.ipproto.udp, gPatterns.facpri51},
    {DC.ipproto.udp, gPatterns.facpri52},
    {DC.ipproto.udp, gPatterns.facpri53},
    {DC.ipproto.udp, gPatterns.facpri54},
    {DC.ipproto.udp, gPatterns.facpri55},
    {DC.ipproto.udp, gPatterns.facpri56},
    {DC.ipproto.udp, gPatterns.facpri57},
    {DC.ipproto.udp, gPatterns.facpri58},
    {DC.ipproto.udp, gPatterns.facpri59},
    {DC.ipproto.udp, gPatterns.facpri60},
    {DC.ipproto.udp, gPatterns.facpri61},
    {DC.ipproto.udp, gPatterns.facpri62},
    {DC.ipproto.udp, gPatterns.facpri63},
    {DC.ipproto.udp, gPatterns.facpri64},
    {DC.ipproto.udp, gPatterns.facpri65},
    {DC.ipproto.udp, gPatterns.facpri66},
    {DC.ipproto.udp, gPatterns.facpri67},
    {DC.ipproto.udp, gPatterns.facpri68},
    {DC.ipproto.udp, gPatterns.facpri69},
    {DC.ipproto.udp, gPatterns.facpri70},
    {DC.ipproto.udp, gPatterns.facpri71},
    {DC.ipproto.udp, gPatterns.facpri72},
    {DC.ipproto.udp, gPatterns.facpri73},
    {DC.ipproto.udp, gPatterns.facpri74},
    {DC.ipproto.udp, gPatterns.facpri75},
    {DC.ipproto.udp, gPatterns.facpri76},
    {DC.ipproto.udp, gPatterns.facpri77},
    {DC.ipproto.udp, gPatterns.facpri78},
    {DC.ipproto.udp, gPatterns.facpri79},
    {DC.ipproto.udp, gPatterns.facpri80},
    {DC.ipproto.udp, gPatterns.facpri81},
    {DC.ipproto.udp, gPatterns.facpri82},
    {DC.ipproto.udp, gPatterns.facpri83},
    {DC.ipproto.udp, gPatterns.facpri84},
    {DC.ipproto.udp, gPatterns.facpri85},
    {DC.ipproto.udp, gPatterns.facpri86},
    {DC.ipproto.udp, gPatterns.facpri87},
    {DC.ipproto.udp, gPatterns.facpri88},
    {DC.ipproto.udp, gPatterns.facpri89},
    {DC.ipproto.udp, gPatterns.facpri90},
    {DC.ipproto.udp, gPatterns.facpri91},
    {DC.ipproto.udp, gPatterns.facpri92},
    {DC.ipproto.udp, gPatterns.facpri93},
    {DC.ipproto.udp, gPatterns.facpri94},
    {DC.ipproto.udp, gPatterns.facpri95},
    {DC.ipproto.udp, gPatterns.facpri96},
    {DC.ipproto.udp, gPatterns.facpri97},
    {DC.ipproto.udp, gPatterns.facpri98},
    {DC.ipproto.udp, gPatterns.facpri99},
    {DC.ipproto.udp, gPatterns.facpri100},
    {DC.ipproto.udp, gPatterns.facpri101},
    {DC.ipproto.udp, gPatterns.facpri102},
    {DC.ipproto.udp, gPatterns.facpri103},
    {DC.ipproto.udp, gPatterns.facpri104},
    {DC.ipproto.udp, gPatterns.facpri105},
    {DC.ipproto.udp, gPatterns.facpri106},
    {DC.ipproto.udp, gPatterns.facpri107},
    {DC.ipproto.udp, gPatterns.facpri108},
    {DC.ipproto.udp, gPatterns.facpri109},
    {DC.ipproto.udp, gPatterns.facpri110},
    {DC.ipproto.udp, gPatterns.facpri111},
    {DC.ipproto.udp, gPatterns.facpri112},
    {DC.ipproto.udp, gPatterns.facpri113},
    {DC.ipproto.udp, gPatterns.facpri114},
    {DC.ipproto.udp, gPatterns.facpri115},
    {DC.ipproto.udp, gPatterns.facpri116},
    {DC.ipproto.udp, gPatterns.facpri117},
    {DC.ipproto.udp, gPatterns.facpri118},
    {DC.ipproto.udp, gPatterns.facpri119},
    {DC.ipproto.udp, gPatterns.facpri120},
    {DC.ipproto.udp, gPatterns.facpri121},
    {DC.ipproto.udp, gPatterns.facpri122},
    {DC.ipproto.udp, gPatterns.facpri123},
    {DC.ipproto.udp, gPatterns.facpri124},
    {DC.ipproto.udp, gPatterns.facpri125},
    {DC.ipproto.udp, gPatterns.facpri126},
    {DC.ipproto.udp, gPatterns.facpri127},
    {DC.ipproto.udp, gPatterns.facpri128},
    {DC.ipproto.udp, gPatterns.facpri129},
    {DC.ipproto.udp, gPatterns.facpri130},
    {DC.ipproto.udp, gPatterns.facpri131},
    {DC.ipproto.udp, gPatterns.facpri132},
    {DC.ipproto.udp, gPatterns.facpri133},
    {DC.ipproto.udp, gPatterns.facpri134},
    {DC.ipproto.udp, gPatterns.facpri135},
    {DC.ipproto.udp, gPatterns.facpri136},
    {DC.ipproto.udp, gPatterns.facpri137},
    {DC.ipproto.udp, gPatterns.facpri138},
    {DC.ipproto.udp, gPatterns.facpri139},
    {DC.ipproto.udp, gPatterns.facpri140},
    {DC.ipproto.udp, gPatterns.facpri141},
    {DC.ipproto.udp, gPatterns.facpri142},
    {DC.ipproto.udp, gPatterns.facpri143},
    {DC.ipproto.udp, gPatterns.facpri144},
    {DC.ipproto.udp, gPatterns.facpri145},
    {DC.ipproto.udp, gPatterns.facpri146},
    {DC.ipproto.udp, gPatterns.facpri147},
    {DC.ipproto.udp, gPatterns.facpri148},
    {DC.ipproto.udp, gPatterns.facpri149},
    {DC.ipproto.udp, gPatterns.facpri150},
    {DC.ipproto.udp, gPatterns.facpri151},
    {DC.ipproto.udp, gPatterns.facpri152},
    {DC.ipproto.udp, gPatterns.facpri153},
    {DC.ipproto.udp, gPatterns.facpri154},
    {DC.ipproto.udp, gPatterns.facpri155},
    {DC.ipproto.udp, gPatterns.facpri156},
    {DC.ipproto.udp, gPatterns.facpri157},
    {DC.ipproto.udp, gPatterns.facpri158},
    {DC.ipproto.udp, gPatterns.facpri159},
    {DC.ipproto.udp, gPatterns.facpri160},
    {DC.ipproto.udp, gPatterns.facpri161},
    {DC.ipproto.udp, gPatterns.facpri162},
    {DC.ipproto.udp, gPatterns.facpri163},
    {DC.ipproto.udp, gPatterns.facpri164},
    {DC.ipproto.udp, gPatterns.facpri165},
    {DC.ipproto.udp, gPatterns.facpri166},
    {DC.ipproto.udp, gPatterns.facpri167},
    {DC.ipproto.udp, gPatterns.facpri168},
    {DC.ipproto.udp, gPatterns.facpri169},
    {DC.ipproto.udp, gPatterns.facpri170},
    {DC.ipproto.udp, gPatterns.facpri171},
    {DC.ipproto.udp, gPatterns.facpri172},
    {DC.ipproto.udp, gPatterns.facpri173},
    {DC.ipproto.udp, gPatterns.facpri174},
    {DC.ipproto.udp, gPatterns.facpri175},
    {DC.ipproto.udp, gPatterns.facpri176},
    {DC.ipproto.udp, gPatterns.facpri177},
    {DC.ipproto.udp, gPatterns.facpri178},
    {DC.ipproto.udp, gPatterns.facpri179},
    {DC.ipproto.udp, gPatterns.facpri180},
    {DC.ipproto.udp, gPatterns.facpri181},
    {DC.ipproto.udp, gPatterns.facpri182},
    {DC.ipproto.udp, gPatterns.facpri183},
    {DC.ipproto.udp, gPatterns.facpri184},
    {DC.ipproto.udp, gPatterns.facpri185},
    {DC.ipproto.udp, gPatterns.facpri186},
    {DC.ipproto.udp, gPatterns.facpri187},
    {DC.ipproto.udp, gPatterns.facpri188},
    {DC.ipproto.udp, gPatterns.facpri189},
    {DC.ipproto.udp, gPatterns.facpri190},
    {DC.ipproto.udp, gPatterns.facpri191},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdSyslog,		         0}
}

flowTrackerTable = {}

function clientInProcess(context)

	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdSyslog);
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.einvalid
end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
	gDetector:client_init()
	appTypeId = 23
	appProductId = 511
	appServiceId = 20020
	--DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

    return gDetector
end

local function isFlowUdp(flowKey)
    local firstInteger = gDetector:htonl(DC.getLongHostFormat(flowKey))
    return (bit.band(firstInteger, DC.flowProtocol.udp) ~= 0)
end

--[[Validator function registered in DetectorInit()
--]]
function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
	context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
	context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('client syslog: packetCount %d, dir %d, size %d\n', context.packetCount, dir, size);

    if (dir == 0 and size > 6 and dstPort == 514) then
        matched = gDetector:getPcreGroups("<(?:[0-9]|[1-9][0-9]|1[0-8][0-9]|19[0-1])>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?: [0-9]|[1-2][0-9]|3[0-1]) (?:[0-1][0-9]|2[0-3])(?::[0-5][0-9]){2}")
        if matched then
            DC.printf ("client syslog: regexp matched\n")
            return clientSuccess(context)
        else 
            DC.printf ("client syslog: regexp did not match\n")
        end
    end

    return clientFail(context)
end

function client_clean()
end

