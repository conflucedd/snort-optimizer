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
detection_name: IEC 60870-5-104
version: 8
description: A SCADA type of protocol, also known as IEC 104. One of the IEC 60870 set of standards which define systems used for telecontrol (supervisory control and data acquisition) in electrical engineering and power system automation applications.
bundle_description: $VAR1 = {
          'IEC 104 List Directory' => 'An IEC 104 Type ID, F_DR_TA_1. List Directory in file transfer.',
          'IEC 104 Setpoint Command Scaled' => 'An IEC 104 Type ID, C_SE_NB_1. Process information in control direction of Setpoint command, scaled value.',
          'IEC 104 Single Point Info' => 'An IEC 104 Type ID, M_SP_NA_1. Process information in monitor direction of Single point information.',
          'IEC 104 Query Log' => 'An IEC 104 Type ID, F_SC_NB_1. Query Log in file transfer.',
          'IEC 104 Regulating Step Command with Long Time' => 'An IEC 104 Type ID, C_RC_TA_1. Command telegrams of Regulating step command with time tag CP56Time2a.',
          'IEC 104 Setpoint Command Normalized with Long Time' => 'An IEC 104 Type ID, C_SE_TA_1. Command telegrams of Setpoint command, normalized value with time tag CP56Time2a.',
          'IEC 104 Single Command' => 'An IEC 104 Type ID, C_SC_NA_1. Process information in control direction of Single command.',
          'IEC 104 Parameter of Measured Scaled' => 'An IEC 104 Type ID, P_ME_NB_1. Parameter in control direction of measured value, scaled value.',
          'IEC 104 Ack File Ack Section' => 'An IEC 104 Type ID, F_AF_NA_1. Act file, Act section in file transfer.',
          'IEC 104 Test Command with Long Time' => 'An IEC 104 Type ID, C_TS_TA_1. System information in control direction of Test command with time tag CP56Time2a.',
          'IEC 104 Measured Short Float with Long Time' => 'An IEC 104 Type ID, M_ME_TF_1. Process telegrams of Measured value, short floating point value with time tag CP56Time2a.',
          'IEC 104 Packed Start Event with Long Time' => 'An IEC 104 Type ID, M_EP_TE_1. Process telegrams of Packed start events of protection equipment with time tag CP56Time2a.',
          'IEC 104 Measured Scaled' => 'An IEC 104 Type ID, M_ME_NB_1. Process information in monitor direction of Measured value, scaled value.',
          'IEC 104 Control Bitstring 32 bits' => 'An IEC 104 Type ID, C_BO_NA_1. Process Information in control direction of Bit string 32 bit.',
          'IEC 104 Reset Process Command' => 'An IEC 104 Type ID, C_RP_NC_1. System information in control direction of Reset process command.',
          'IEC 104 List Segment' => 'An IEC 104 Type ID, F_SG_NA_1. List Segment in file transfer.',
          'IEC 104 STARTDT ACT' => 'An IEC 104 Function of Start Data Transfer Activation.',
          'IEC 104 Call directory Select File' => 'An IEC 104 Type ID, F_SC_NA_1. Call directory, select file, call file, call section.',
          'IEC 104 TESTFR ACT' => 'An IEC 104 Function of Test Frame Activation.',
          'IEC 104 Bitstring 32 bit Command with Long Time' => 'An IEC 104 Type ID, C_BO_TA_1. Command telegrams of Bit string 32 bit with time tag CP56Time2a.',
          'IEC 104 Double Point Info with Long Time' => 'An IEC 104 Type ID, M_DP_TB_1. Process telegrams of Double point information with time tag CP56Time2a.',
          'IEC 104 Regulating Step Command' => 'An IEC 104 Type ID, C_RC_NA_1. Process information in control direction of Regulating step command.',
          'IEC 104 Event of Protection with Long Time' => 'An IEC 104 Type ID, M_EP_TD_1. Process telegrams of Event of protection equipment with time tag CP56Time2a.',
          'IEC 104 Bitstring 32 bit with Long Time' => 'An IEC 104 Type ID, M_BO_TB_1. Process telegrams of Bit string of 32 bit with time tag CP56Time2a.',
          'IEC 104 Double Command' => 'An IEC 104 Type ID, C_DC_NA_1. Process Information in control direction of Double command.',
          'IEC 104 STARTDT CON' => 'An IEC 104 Function of Start Data Transfer Confirmation.',
          'IEC 104 Parameter of Measured Normalized' => 'An IEC 104 Type ID, P_ME_NA_1. Parameter in control direction of measured value, normalized value.',
          'IEC 104 Step Position Info' => 'An IEC 104 Type ID, M_ST_NA_1. Process information in monitor direction of Step position information.',
          'IEC 104 Measured Normalized with Long Time' => 'An IEC 104 Type ID, M_ME_TD_1. Process telegrams of Measured value, normalized value with time tag CP56Time2a.',
          'IEC 104 Step Position Info with Long Time' => 'An IEC 104 Type ID, M_ST_TB_1. Process telegrams of Step position information with time tag CP56Time2a.',
          'IEC 104 File Ready' => 'An IEC 104 Type ID, F_FR_NA_1. File ready in file transfer.',
          'IEC 104 Packed Output Circuit Info with Long Time' => 'An IEC 104 Type ID, M_EP_TF_1. Process telegrams of Packed output circuit information of protection equipment with time tag CP56Time2a.',
          'IEC 104 Measured Short Float' => 'An IEC 104 Type ID, M_ME_NC_1. Process information in monitor direction of Measured value, short floating point value.',
          'IEC 104 Double Point Info' => 'An IEC 104 Type ID, M_DP_NA_1. Process information in monitor direction of Double point information.',
          'IEC 104 Interrogation Command' => 'An IEC 104 Type ID, C_IC_NA_1. System Information in control direction of General Interrogation command.',
          'IEC 104 Measured Scaled with Long Time' => 'An IEC 104 Type ID, M_ME_TE_1. Process telegrams of Measured value, scaled value with time tag CP56Time2a.',
          'IEC 104 Last Section Last Segment' => 'An IEC 104 Type ID, F_LS_NA_1. Last section, last segment in file transfer.',
          'IEC 104 Monitor Bitstring 32 bit' => 'An IEC 104 Type ID, M_BO_NA_1. Process information in monitor direction of Bit string of 32 bit.',
          'IEC 104 Measured Normalized without Quality Descriptor' => 'An IEC 104 Type ID, M_ME_ND_1. Process information in monitor direction of Measured value, normalized value without quality descriptor.',
          'IEC 104 Integrated Totals with Long Time' => 'An IEC 104 Type ID, M_IT_TB_1. Process telegrams of Integrated totals with time tag CP56Time2a.',
          'IEC 104 Clock Synchronization Command' => 'An IEC 104 Type ID, C_CS_NA_1. System information in control direction of Clock synchronization command.',
          'IEC 104 Setpoint Command Short Float' => 'An IEC 104 Type ID, C_SE_NC_1. Process information in control direction of Setpoint command, short floating point value.',
          'IEC 104 Single Point Info with Long Time' => 'An IEC 104 Type ID, M_SP_TB_1. Process telegrams of Single point information with time tag CP56Time2a.',
          'IEC 104 Read Command' => 'An IEC 104 Type ID, C_RD_NA_1. System information in control direction of Read command.',
          'IEC 104 Counter Interrogation Command' => 'An IEC 104 Type ID, C_CI_NA_1. System information in control direction of Counter interrogation command.',
          'IEC 104 TESTFR CON' => 'An IEC 104 Function of Test Frame Confirmation.',
          'IEC 104 End of Initialization' => 'An IEC 104 Type ID, M_EI_NA_1. System information in monitor direction of End of initialization.',
          'IEC 104 Integrated Totals' => 'An IEC 104 Type ID, M_IT_NA_1. Process information in monitor direction of Integrated totals.',
          'IEC 104 Measured Normalized' => 'An IEC 104 Type ID, M_ME_NA_1. Process information in monitor direction of Measured value, normalized value.',
          'IEC 104 Packed Single Point' => 'An IEC 104 Type ID, M_PS_NA_1. Process information in monitor direction of Packed single-point information with status change detection.',
          'IEC 104 Section Ready' => 'An IEC 104 Type ID, F_SR_NA_1. Section ready in file transfer.',
          'IEC 104 Setpoint Command Scaled with Long Time' => 'An IEC 104 Type ID, C_SE_TB_1. Command telegrams of Setpoint command, scaled value with time tag CP56Time2a.',
          'IEC 104 Parameter Activation' => 'An IEC 104 Type ID, P_AC_NA_1. Parameter in control direction of Parameter activation.',
          'IEC 104 Single Command with Long Time' => 'An IEC 104 Type ID, C_SC_TA_1. Command telegrams of Single command with time tag CP56Time2a.',
          'IEC 104 Double Command with Long Time' => 'An IEC 104 Type ID, C_DC_TA_1. Command telegrams of Double command with time tag CP56Time2a.',
          'IEC 104 Parameter of Measured Short Float' => 'An IEC 104 Type ID, P_ME_NC_1. Parameter in control direction of measured value, short floating point value.',
          'IEC 104 Setpoint Command Normalized' => 'An IEC 104 Type ID, C_SE_NA_1. Process information in control direction of Setpoint command, normalized value.',
          'IEC 60870-5-104' => 'A SCADA type of protocol, also known as IEC 104. One of the IEC 60870 set of standards which define systems used for telecontrol (supervisory control and data acquisition) in electrical engineering and power system automation applications.',
          'IEC 104 Setpoint Command Short Float with Long Time' => 'An IEC 104 Type ID, C_SE_TC_1. Command telegrams of Setpoint command, short floating point value with time tag CP56Time2a.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "IEC 60870-5-104",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceIdIEC104 = 20191
gServiceName = 'IEC 60870-5-104'

gSfAppIdIEC104 = 3778
gSfAppIdIEC104CSCNA1 = 5020
gSfAppIdIEC104CBONA1 = 5022
gSfAppIdIEC104CDCNA1 = 5023
gSfAppIdIEC104CICNA1 = 5024
gSfAppIdIEC104CRCNA1 = 5025
gSfAppIdIEC104CSENA1 = 5026
gSfAppIdIEC104CSENB1 = 5027
gSfAppIdIEC104CSENC1 = 5028
gSfAppIdIEC104MEINA1 = 5029
gSfAppIdIEC104MMETD1 = 5030
gSfAppIdIEC104MSPTB1 = 5031
gSfAppIdIEC104MSTNA1 = 5032
gSfAppIdIEC104TESTFRCON = 5033
gSfAppIdIEC104TESTFRACT = 5034
gSfAppIdIEC104STARTDTCON = 5035
gSfAppIdIEC104STARTDTACT = 5036
gSfAppIdIEC104MDPNA1 = 5037
gSfAppIdIEC104MBONA1 = 5038
gSfAppIdIEC104MMENA1 = 5039
gSfAppIdIEC104MMENB1 = 5040
gSfAppIdIEC104MITNA1 = 5041
gSfAppIdIEC104MPSNA1 = 5042
gSfAppIdIEC104MMEND1 = 5043
gSfAppIdIEC104MDPTB1 = 5044
gSfAppIdIEC104MMENC1 = 5045
gSfAppIdIEC104MSPNA1 = 5046
gSfAppIdIEC104MSTTB1 = 5047
gSfAppIdIEC104MBOTB1 = 5048
gSfAppIdIEC104MMETE1 = 5049
gSfAppIdIEC104MMETF1 = 5050
gSfAppIdIEC104MITTB1 = 5051
gSfAppIdIEC104MEPTD1 = 5052
gSfAppIdIEC104MEPTE1 = 5053
gSfAppIdIEC104MEPTF1 = 5054
gSfAppIdIEC104CSCTA1 = 5055
gSfAppIdIEC104CDCTA1 = 5056
gSfAppIdIEC104CRCTA1 = 5057
gSfAppIdIEC104CSETA1 = 5058
gSfAppIdIEC104CSETB1 = 5059
gSfAppIdIEC104CSETC1 = 5060
gSfAppIdIEC104CBOTA1 = 5061
gSfAppIdIEC104CCINA1 = 5062
gSfAppIdIEC104CRDNA1 = 5063
gSfAppIdIEC104CCSNA1 = 5064
gSfAppIdIEC104CRPNC1 = 5065
gSfAppIdIEC104CTSTA1 = 5066
gSfAppIdIEC104PMENA1 = 5067
gSfAppIdIEC104PMENB1 = 5068
gSfAppIdIEC104PMENC1 = 5069
gSfAppIdIEC104PACNA1 = 5070
gSfAppIdIEC104FFRNA1 = 5071
gSfAppIdIEC104FSRNA1 = 5072
gSfAppIdIEC104FSCNA1 = 5073
gSfAppIdIEC104FLSNA1 = 5074
gSfAppIdIEC104FAFNA1 = 5075
gSfAppIdIEC104FSGNA1 = 5076
gSfAppIdIEC104FDRTA1 = 5077
gSfAppIdIEC104FSCNB1 = 5078

gPorts = {
    {DC.ipproto.tcp, 2404},
}

gAppRegistry = {
    {gSfAppIdIEC104, 0},
    {gSfAppIdIEC104CBONA1, 0},
    {gSfAppIdIEC104CDCNA1, 0},
    {gSfAppIdIEC104CICNA1, 0},
    {gSfAppIdIEC104CRCNA1, 0},
    {gSfAppIdIEC104CSENA1, 0},
    {gSfAppIdIEC104CSENB1, 0},
    {gSfAppIdIEC104CSENC1, 0},
    {gSfAppIdIEC104MEINA1, 0},
    {gSfAppIdIEC104MMETD1, 0},
    {gSfAppIdIEC104MSPTB1, 0},
    {gSfAppIdIEC104MSTNA1, 0},
    {gSfAppIdIEC104TESTFRCON, 0},
    {gSfAppIdIEC104TESTFRACT, 0},
    {gSfAppIdIEC104STARTDTCON, 0},
    {gSfAppIdIEC104STARTDTACT, 0},
    {gSfAppIdIEC104CSCNA1, 0},
    {gSfAppIdIEC104MMENC1, 0},
    {gSfAppIdIEC104MSPNA1, 0},
    {gSfAppIdIEC104MDPNA1, 0},
    {gSfAppIdIEC104MBONA1, 0},
    {gSfAppIdIEC104MMENA1, 0},
    {gSfAppIdIEC104MMENB1, 0},
    {gSfAppIdIEC104MITNA1, 0},
    {gSfAppIdIEC104MPSNA1, 0},
    {gSfAppIdIEC104MMEND1, 0},
    {gSfAppIdIEC104MDPTB1, 0},
    {gSfAppIdIEC104MSTTB1, 0},
    {gSfAppIdIEC104MBOTB1, 0},
    {gSfAppIdIEC104MMETE1, 0},
    {gSfAppIdIEC104MMETF1, 0},
    {gSfAppIdIEC104MITTB1, 0},
    {gSfAppIdIEC104MEPTD1, 0},
    {gSfAppIdIEC104MEPTE1, 0},
    {gSfAppIdIEC104MEPTF1, 0},
    {gSfAppIdIEC104CSCTA1, 0},
    {gSfAppIdIEC104CDCTA1, 0},
    {gSfAppIdIEC104CRCTA1, 0},
    {gSfAppIdIEC104CSETA1, 0},
    {gSfAppIdIEC104CSETB1, 0},
    {gSfAppIdIEC104CSETC1, 0},
    {gSfAppIdIEC104CBOTA1, 0},
    {gSfAppIdIEC104CCINA1, 0},
    {gSfAppIdIEC104CRDNA1, 0},
    {gSfAppIdIEC104CCSNA1, 0},
    {gSfAppIdIEC104CRPNC1, 0},
    {gSfAppIdIEC104CTSTA1, 0},
    {gSfAppIdIEC104PMENA1, 0},
    {gSfAppIdIEC104PMENB1, 0},
    {gSfAppIdIEC104PMENC1, 0},
    {gSfAppIdIEC104PACNA1, 0},
    {gSfAppIdIEC104FFRNA1, 0},
    {gSfAppIdIEC104FSRNA1, 0},
    {gSfAppIdIEC104FSCNA1, 0},
    {gSfAppIdIEC104FLSNA1, 0},
    {gSfAppIdIEC104FAFNA1, 0},
    {gSfAppIdIEC104FSGNA1, 0},
    {gSfAppIdIEC104FDRTA1, 0},
    {gSfAppIdIEC104FSCNB1, 0},
}


TIDPatterns = {
    {"\051", gSfAppIdIEC104CBONA1}, -- C_BO_NA_1 0x33
    {"\046", gSfAppIdIEC104CDCNA1}, -- C_DC_NA_1 0x2E
    {"\100", gSfAppIdIEC104CICNA1}, -- C_IC_NA_1 0x64
    {"\047", gSfAppIdIEC104CRCNA1}, -- C_RC_NA_1 0x2F
    {"\048", gSfAppIdIEC104CSENA1}, -- C_SE_NA_1 0x30
    {"\049", gSfAppIdIEC104CSENB1}, -- C_SE_NB_1 0x31
    {"\050", gSfAppIdIEC104CSENC1}, -- C_SE_NC_1 0x32
    {"\070", gSfAppIdIEC104MEINA1}, -- M_EI_NA_1 0x46
    {"\034", gSfAppIdIEC104MMETD1}, -- M_ME_TD_1 0x22
    {"\030", gSfAppIdIEC104MSPTB1}, -- M_SP_TB_1 0x1E
    {"\005", gSfAppIdIEC104MSTNA1}, -- M_ST_NA_1 0x05
    {"\045", gSfAppIdIEC104CSCNA1}, -- C_SC_NA_1 0x2D
    {"\001", gSfAppIdIEC104MSPNA1}, -- M_SP_NA_1 0x01
    {"\013", gSfAppIdIEC104MMENC1}, -- M_ME_NC_1 0x0D
    {"\003", gSfAppIdIEC104MDPNA1}, -- M_DP_NA_1 0x03
    {"\007", gSfAppIdIEC104MBONA1}, -- M_BO_NA_1 0x07
    {"\009", gSfAppIdIEC104MMENA1}, -- M_ME_NA_1 0x09
    {"\011", gSfAppIdIEC104MMENB1}, -- M_ME_NB_1 0x0B
    {"\015", gSfAppIdIEC104MITNA1}, -- M_IT_NA_1 0x0F
    {"\020", gSfAppIdIEC104MPSNA1}, -- M_PS_NA_1 0x14
    {"\021", gSfAppIdIEC104MMEND1}, -- M_ME_ND_1 0x15
    {"\031", gSfAppIdIEC104MDPTB1}, -- M_DP_TB_1 0x1F
    {"\032", gSfAppIdIEC104MSTTB1}, -- M_ST_TB_1 0x20
    {"\033", gSfAppIdIEC104MBOTB1}, -- M_BO_TB_1 0x21
    {"\035", gSfAppIdIEC104MMETE1}, -- M_ME_TE_1 0x23
    {"\036", gSfAppIdIEC104MMETF1}, -- M_ME_TF_1 0x24
    {"\037", gSfAppIdIEC104MITTB1}, -- M_IT_TB_1 0x25
    {"\038", gSfAppIdIEC104MEPTD1}, -- M_EP_TD_1 0x26
    {"\039", gSfAppIdIEC104MEPTE1}, -- M_EP_TE_1 0x27
    {"\040", gSfAppIdIEC104MEPTF1}, -- M_EP_TF_1 0x28
    {"\058", gSfAppIdIEC104CSCTA1}, -- C_SC_TA_1 0x3A
    {"\059", gSfAppIdIEC104CDCTA1}, -- C_DC_TA_1 0x3B
    {"\060", gSfAppIdIEC104CRCTA1}, -- C_RC_TA_1 0x3C
    {"\061", gSfAppIdIEC104CSETA1}, -- C_SE_TA_1 0x3D
    {"\062", gSfAppIdIEC104CSETB1}, -- C_SE_TB_1 0x3E
    {"\063", gSfAppIdIEC104CSETC1}, -- C_SE_TC_1 0x3F
    {"\064", gSfAppIdIEC104CBOTA1}, -- C_BO_TA_1 0x40
    {"\101", gSfAppIdIEC104CCINA1}, -- C_CI_NA_1 0x65
    {"\102", gSfAppIdIEC104CRDNA1}, -- C_RD_NA_1 0x66
    {"\103", gSfAppIdIEC104CCSNA1}, -- C_CS_NA_1 0x67
    {"\105", gSfAppIdIEC104CRPNC1}, -- C_RP_NC_1 0x69
    {"\107", gSfAppIdIEC104CTSTA1}, -- C_TS_TA_1 0x6B
    {"\110", gSfAppIdIEC104PMENA1}, -- P_ME_NA_1 0x6E
    {"\111", gSfAppIdIEC104PMENB1}, -- P_ME_NB_1 0x6F
    {"\112", gSfAppIdIEC104PMENC1}, -- P_ME_NC_1 0x70
    {"\113", gSfAppIdIEC104PACNA1}, -- P_AC_NA_1 0x71
    {"\120", gSfAppIdIEC104FFRNA1}, -- F_FR_NA_1 0x78
    {"\121", gSfAppIdIEC104FSRNA1}, -- F_SR_NA_1 0x79
    {"\122", gSfAppIdIEC104FSCNA1}, -- F_SC_NA_1 0x7A
    {"\123", gSfAppIdIEC104FLSNA1}, -- F_LS_NA_1 0x7B
    {"\124", gSfAppIdIEC104FAFNA1}, -- F_AF_NA_1 0x7C
    {"\125", gSfAppIdIEC104FSGNA1}, -- F_SG_NA_1 0x7D
    {"\126", gSfAppIdIEC104FDRTA1}, -- F_DR_TA_1 0x7E
    {"\127", gSfAppIdIEC104FSCNB1}, -- F_SC_NB_1 0x7F
}

FuncPatterns = {
    {"\067", gSfAppIdIEC104TESTFRACT},
    {"\131", gSfAppIdIEC104TESTFRCON},
    {"\007", gSfAppIdIEC104STARTDTACT},
    {"\011", gSfAppIdIEC104STARTDTCON},
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:inProcessService()
    end
    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        DC.printf('%s: adding service\n', gServiceName)
        gDetector:addService(gServiceIdIEC104, "IEC", "", gSfAppIdIEC104)
    end
    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:failService()
    end
    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',gServiceName)
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end

local function checkStart(index)
    start_ptn = "\104" -- 0x68
    if gDetector:memcmp(start_ptn, #start_ptn, index) == 0 then
        return 1
    else
        return nil
    end
end

local function checkTID(index)
    for i = 1, #TIDPatterns do
        if gDetector:memcmp(TIDPatterns[i][1], #TIDPatterns[i][1], index) == 0 then
            return TIDPatterns[i][2]
        end
    end
    return nil
end

local function checkFunc(index)
    for i = 1, #FuncPatterns do
        if gDetector:memcmp(FuncPatterns[i][1], #FuncPatterns[i][1], index) == 0 then
            return FuncPatterns[i][2]
        end
    end
    return nil
end

function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    if size == 0 then
        return serviceInProcess(context)
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size)

    found = 0
    report_payload_id = 0

    if size >= 6 then
        -- there can be more than one ASDU per packet, but for now we will assume there is one
        start_index = 0
        if checkStart(start_index) and (srcPort == 2404 or dstPort == 2404) then
            func_index = 2
            func_id = checkFunc(func_index)
            if func_id then
                found = 1
                report_payload_id = func_id
            end

            tid_index = 6
            if found == 0 and size >= tid_index + 1 then
                tid = checkTID(tid_index)
                if tid then
                    found = 1
                    report_payload_id = tid
                end
            end

            if found == 1 then
                DC.printf('%s:Adding payload %d\n',gServiceName, report_payload_id)
                gDetector:service_analyzePayload(report_payload_id)
            end

            -- if we are on port 2404 and we saw the start pattern, we know its iec104
            -- so set the continue flag (to keep looking for messages) and declare success.
            context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
            return serviceSuccess(context)
        end
    end

    return serviceFail(context)

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
