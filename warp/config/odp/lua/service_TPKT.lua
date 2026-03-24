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
detection_name: TPKT
version: 17
description: A protocol used to tunnel OSI protocols over TCP/IP.
bundle_description: $VAR1 = {
          'MMS deleteEventEnrollment' => 'An MMS Command of Delete Event Enrollment request.',
          'MMS reportSemaphoreEntryStatus' => 'An MMS Command of Report Semaphore Entry Status request.',
          'MMS reportEventActionStatus' => 'An MMS Command of Report Event Action Status request.',
          'MMS status' => 'An MMS Command of Status request.',
          'MMS reportPoolSemaphoreStatus' => 'An MMS Command of Report Pool Semaphore Status request.',
          'MMS getVariableAccAttr' => 'An MMS Command of Get Variable Access Attributes request.',
          'MMS reportEventConditionStatus' => 'An MMS Command of Report Event Condition Status request.',
          'MMS deleteDomain' => 'An MMS Command of Delete Domain request.',
          'MMS getEventActionAttr' => 'An MMS Command of Get Event Action Attributes request.',
          'MMS start' => 'An MMS Command of Start request.',
          'MMS fileRename' => 'An MMS Command of File Rename request.',
          'MMS readJournal' => 'An MMS Command of Read Journal request.',
          'MMS deleteNamedType' => 'An MMS Command of Delete Named Type request.',
          'MMS deleteSemaphore' => 'An MMS Command of Delete Semaphore request.',
          'MMS getProgramInvocationAttr' => 'An MMS Command of Get Program Invocation Attributes request.',
          'MMS reportEventEnrollmentStatus' => 'An MMS Command of Report Event Enrollment Status request.',
          'MMS uploadSegment' => 'An MMS Command of Upload Segment request.',
          'MMS confirmedResponsePDU' => 'An MMS Confirmed Response PDU message.',
          'MMS storeDomainContent' => 'An MMS Command of Store Domain Content request.',
          'TPKT' => 'A protocol used to tunnel OSI protocols over TCP/IP.',
          'MMS takeControl' => 'An MMS Command of Take Control request.',
          'MMS initiateUploadSequence' => 'An MMS Command of Initiate Upload Sequence request.',
          'S7CommPlus' => 'A Siemens branded proprietary comms protocol.',
          'MMS defineNamedVariable' => 'An MMS Command of Define Named Variable request.',
          'MMS output' => 'An MMS Command of Output request.',
          'MMS deleteVariableAccess' => 'An MMS Command of Delete Variable Access request.',
          'MMS reportJournalStatus' => 'An MMS Command of Report Journal Status request.',
          'MMS getAlarmEnrollmentSummary' => 'An MMS Command of Get Alarm Enrollment Summary request.',
          'MMS domainUpload' => 'An MMS Command of Request Domain Upload.',
          'MMS defineEventEnrollment' => 'An MMS Command of Define Event Enrollment request.',
          'MMS getEventEnrollmentAttr' => 'An MMS Command of Get Event Enrollment Attributes request.',
          'RDP' => 'Remote Desktop Protocol provides users with a graphical interface to another computer.',
          'MMS fileOpen' => 'An MMS Command of File Open request.',
          'MMS writeJournal' => 'An MMS Command of Write Journal request.',
          'MMS rename' => 'An MMS Command of Rename request.',
          'MMS getDomainAttributes' => 'An MMS Command of Get Domain Attributes request.',
          'MMS input' => 'An MMS Command of Input request.',
          'MMS getNamedTypeAttr' => 'An MMS Command of Get Named Type Attributes request.',
          'MMS write' => 'An MMS Command of Write request.',
          'MMS relinquishControl' => 'An MMS Command of Relinquish Control request.',
          'MMS defineScatteredAccess' => 'An MMS Command of Define Scattered Access request.',
          'MMS getAlarmSummary' => 'An MMS Command of Get Alarm Summary request.',
          'MMS defineSemaphore' => 'An MMS Command of Define Semaphore request.',
          'MMS fileRead' => 'An MMS Command of File Read request.',
          'MMS alterEventConditionMonitoring' => 'An MMS Command of Alter Event Condition Monitoring request.',
          'MMS unconfirmedPDU' => 'An MMS Unconfirmed PDU message.',
          'MMS stop' => 'An MMS Command of stop request.',
          'MMS fileDirectory' => 'An MMS Command of File Directory request.',
          'MMS triggerEvent' => 'An MMS Command of Trigger Event request.',
          'MMS initiateDownloadSequence' => 'An MMS Command of Initiate Download Sequence request.',
          'MMS identify' => 'An MMS Command of Identify request.',
          'MMS createProgramInvocation' => 'An MMS Command of Create Program Invocation request.',
          'MMS getNamedVariableListAttr' => 'An MMS Command of Get Named Variable List Attributes request.',
          'MMS deleteEventAction' => 'An MMS Command of Delete Event Action request.',
          'MMS ackEventNotificaton' => 'An MMS Command of Acknowledge Event Notification request.',
          'MMS getCapabilityList' => 'An MMS Command of Get Capability List request.',
          'MMS getScatteredAccessAttr' => 'An MMS Command of Get Scattered Access Attributes request.',
          'MMS defineEventAction' => 'An MMS Command of Define Event Action request.',
          'MMS downloadSegment' => 'An MMS Command of Download Segment request.',
          'MMS defineEventCondition' => 'An MMS Command of Define Event Condition request.',
          'MMS confirmedErrorPDU' => 'An MMS Confirmed Error PDU message.',
          'MMS kill' => 'An MMS Command of Kill request.',
          'COTP' => 'Connection-oriented ISO protocol.',
          'MMS deleteNamedVariableList' => 'An MMS Command of Delete Named Variable List request.',
          'MMS resume' => 'An MMS Command of Resume request.',
          'MMS terminateUploadSequence' => 'An MMS Command of Terminate Upload Sequence request.',
          'MMS getNameList' => 'An MMS command of Get Name List request.',
          'MMS createJournal' => 'An MMS Command of Create Journal request.',
          'MMS terminateDownloadSequence' => 'An MMS Command of Terminate Download Sequence request.',
          'MMS defineNamedType' => 'An MMS Command of Define Named Type request.',
          'MMS deleteProgramInvocation' => 'An MMS Command of Delete Program Invocation request.',
          'MMS defineNamedVariableList' => 'An MMS Command of Define Named Variable List request.',
          'MMS alterEventEnrollment' => 'An MMS Command of Alter Event Enrollment request.',
          'MMS read' => 'An MMS Command of Read request.',
          'MMS domainDownload' => 'An MMS Command of Request Domain Download.',
          'MMS reportSemaphoreStatus' => 'An MMS Command of Report Semaphore Status request.',
          'ISO MMS' => 'Manufacturer Messaging Specification, the ISO session-layer protocol.',
          'ITU H.323' => 'Packet-based mulimedia conferencing protocol.',
          'MMS getEventConditionAttr' => 'An MMS Command of Get Event Condition Attributes request.',
          'MMS obtainFile' => 'An MMS Command of Obtain File request.',
          'MMS reset' => 'An MMS Command of Reset request.',
          'MMS deleteJournal' => 'An MMS Command of Delete Journal request.',
          'Q.931' => 'ISO standard signalling protocol.',
          'MMS loadDomainContent' => 'An MMS Command of Load Domain Content request.',
          'MMS fileDelete' => 'An MMS Command of File Delete request.',
          'MMS deleteEventCondition' => 'An MMS Command of Delete Event Condition request.',
          'MMS initializeJournal' => 'An MMS Command of Initialize Journal request.',
          'MMS fileClose' => 'An MMS Command of File Close request.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "TPKT",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

apps = {
    tpkt = {
        app_id = 2311,
        svc_id = 20162,
    },
    cotp = {
        app_id = 2312,
        svc_id = 20164,
    },
    isomms = {
        app_id = 2313,
        svc_id = 20165,
    },
    q931 = {
        app_id = 2314,
        svc_id = 20166,
    },
    h225 = {
        app_id = 193,
        svc_id = 20210,
    },
    h245 = {
        app_id = 194,
        svc_id = 20211,
    },
    rdp = {
        app_id = 803,
        svc_id = 20029,
    },
    rtp = {
        app_id = 813,
        svc_id = 20032,
    },
    h323 = {
        app_id = 688,
        -- no svc_id because this is a web app
    },
    s7commplus = {
        app_id = 7357,
        svc_id = 20219, 
    },
}

-- ITU protocol identifiers - because the identifier for h225 is at a variable index,
-- we will use a regexp for it instead of adding it to the gPatterns table.
h225_identifier = "\000\008\145\074\000\004"
h245_identifier = "\000\008\129\117\000\005"

-- marks the end of an S7CommPlus packet
s7commplus_tail = "\000\000\114\001\000\000"

gPatterns = {
    tpkt = { "\003\000", 0, apps.tpkt.app_id},
    q931 = { "\008\002", 4, apps.tpkt.app_id},
    h245 = { h245_identifier, 8, apps.tpkt.app_id},
    open_logical_channel_ack = { "\034\192", 4, apps.tpkt.app_id},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.tpkt},
    {DC.ipproto.tcp, gPatterns.q931},
}

gPorts = {
    {DC.ipproto.tcp, 102},
    {DC.ipproto.tcp, 3389},
    {DC.ipproto.tcp, 1718},
    {DC.ipproto.udp, 1718},
    {DC.ipproto.tcp, 1719},
    {DC.ipproto.udp, 1719},
    {DC.ipproto.tcp, 1720},
    {DC.ipproto.udp, 1720},
}

gAppRegistry = {
    {apps.tpkt.app_id, 0},
    {apps.cotp.app_id, 0},
    {apps.q931.app_id, 0},
    {apps.isomms.app_id, 0},
    {apps.h225.app_id, 0},
    {apps.h245.app_id, 0},
    {apps.s7commplus.app_id, 0},
}

--[[ ISO MMS Section
    Add your new appid to the list here.
    Add the command and message id to the MMSMsgs table below.
--]]

app_id_MMSgetNameList  = 5021
app_id_MMSunconfirmed  = 5101
app_id_MMSconfirmedRes = 5102
app_id_MMSread         = 5103
app_id_MMSwrite        = 5104
app_id_MMSgetVaAccAttr = 5105
app_id_MMSgetNameVaLi  = 5106
app_id_MMSconfirmedErr = 5107
app_id_MMSstatus             = 5108
app_id_MMSidentify           = 5109
app_id_MMSrename             = 5110
app_id_MMSdefNamedVa         = 5111
app_id_MMSdefScatAcc         = 5112
app_id_MMSgetScatAccAttr     = 5113
app_id_MMSdelVaAccess        = 5114
app_id_MMSdefNamedVaList     = 5115
app_id_MMSdelNamedVaList     = 5116
app_id_MMSdefNamedType       = 5117
app_id_MMSgetNamedTypeAttr   = 5118
app_id_MMSdelNamedType       = 5119
app_id_MMSinput              = 5120
app_id_MMSoutput             = 5121
app_id_MMStakeControl        = 5122
app_id_MMSrelinquishControl  = 5123
app_id_MMSdefSemaphore       = 5124
app_id_MMSdelSemaphore       = 5125
app_id_MMSrepSemaphoreSt     = 5126
app_id_MMSrepPoolSemaphoreSt = 5127
app_id_MMSrepSemaphoreEnSt   = 5128
app_id_MMSinitDlSeq          = 5129
app_id_MMSdlSegment          = 5130
app_id_MMStermDlSeq          = 5131
app_id_MMSinitUlSeq          = 5132
app_id_MMSulSegment          = 5133
app_id_MMStermUlSeq          = 5134
app_id_MMSdomainDl           = 5135
app_id_MMSdomainUl           = 5136
app_id_MMSldDomainCont       = 5137
app_id_MMSstDomainCont       = 5138
app_id_MMSdelDomain          = 5139
app_id_MMSgetDomainAttr      = 5140
app_id_MMScrtProgInvoc       = 5141
app_id_MMSdelProgInvoc       = 5142
app_id_MMSstart              = 5143
app_id_MMSstop               = 5144
app_id_MMSresume             = 5145
app_id_MMSreset              = 5146
app_id_MMSkill               = 5147
app_id_MMSgetProgInvocAttr   = 5148
app_id_MMSobtainFile         = 5149
app_id_MMSdefEventCond       = 5150
app_id_MMSdelEventCond       = 5151
app_id_MMSgetEventCondAttr   = 5152
app_id_MMSrepEventCondSt     = 5153
app_id_MMSaltEventCondMon    = 5154
app_id_MMStriggerEvent       = 5155
app_id_MMSdefEventAction     = 5156
app_id_MMSdelEventAction     = 5157
app_id_MMSgetEventActionAttr = 5158
app_id_MMSrepEventActionSt   = 5159
app_id_MMSdefEventEnrol      = 5160
app_id_MMSdelEventEnrol      = 5161
app_id_MMSaltEventEnrol      = 5162
app_id_MMSrepEventEnrolSt    = 5163
app_id_MMSgetEventEnrolAttr  = 5164
app_id_MMSackEventNot        = 5165
app_id_MMSgetAlarmSum        = 5166
app_id_MMSgetAlarmEnrolSum   = 5167
app_id_MMSreadJournal        = 5168
app_id_MMSwriteJournal       = 5169
app_id_MMSinitJournal        = 5170
app_id_MMSrepJournalSt       = 5171
app_id_MMScrtJournal         = 5172
app_id_MMSdelJournal         = 5173
app_id_MMSgetCapList         = 5174
app_id_MMSfileOpen           = 5175
app_id_MMSfileRead           = 5176
app_id_MMSfileClose          = 5177
app_id_MMSfileRename         = 5178
app_id_MMSfileDelete         = 5179
app_id_MMSfileDir            = 5180

MMSmsgs = {
    { "\160", "\161", app_id_MMSgetNameList },
    { "\160", "\164", app_id_MMSread         },
    { "\160", "\165", app_id_MMSwrite        },
    { "\160", "\166", app_id_MMSgetVaAccAttr },
    { "\160", "\172", app_id_MMSgetNameVaLi  },
    { "\160", "\128", app_id_MMSstatus             },
    { "\160", "\130", app_id_MMSidentify           },
    { "\160", "\163", app_id_MMSrename             },
    { "\160", "\167", app_id_MMSdefNamedVa         },
    { "\160", "\168", app_id_MMSdefScatAcc         },
    { "\160", "\169", app_id_MMSgetScatAccAttr     },
    { "\160", "\170", app_id_MMSdelVaAccess        },
    { "\160", "\171", app_id_MMSdefNamedVaList     },
    { "\160", "\173", app_id_MMSdelNamedVaList     },
    { "\160", "\174", app_id_MMSdefNamedType       },
    { "\160", "\175", app_id_MMSgetNamedTypeAttr   },
    { "\160", "\176", app_id_MMSdelNamedType       },
    { "\160", "\177", app_id_MMSinput              },
    { "\160", "\178", app_id_MMSoutput             },
    { "\160", "\179", app_id_MMStakeControl        },
    { "\160", "\180", app_id_MMSrelinquishControl  },
    { "\160", "\181", app_id_MMSdefSemaphore       },
    { "\160", "\182", app_id_MMSdelSemaphore       },
    { "\160", "\183", app_id_MMSrepSemaphoreSt     },
    { "\160", "\184", app_id_MMSrepPoolSemaphoreSt },
    { "\160", "\185", app_id_MMSrepSemaphoreEnSt   },
    { "\160", "\186", app_id_MMSinitDlSeq          },
    { "\160", "\155", app_id_MMSdlSegment          },
    { "\160", "\188", app_id_MMStermDlSeq          },
    { "\160", "\157", app_id_MMSinitUlSeq          },
    { "\160", "\158", app_id_MMSulSegment          },
    { "\160", "\159\031", app_id_MMStermUlSeq       },
    { "\160", "\191\032", app_id_MMSdomainDl        },
    { "\160", "\191\033", app_id_MMSdomainUl        },
    { "\160", "\191\034", app_id_MMSldDomainCont    },
    { "\160", "\191\035", app_id_MMSstDomainCont    },
    { "\160", "\159\036", app_id_MMSdelDomain       },
    { "\160", "\159\037", app_id_MMSgetDomainAttr   },
    { "\160", "\191\038", app_id_MMScrtProgInvoc    },
    { "\160", "\159\039", app_id_MMSdelProgInvoc    },
    { "\160", "\191\040", app_id_MMSstart           },
    { "\160", "\191\041", app_id_MMSstop            },
    { "\160", "\191\042", app_id_MMSresume          },
    { "\160", "\191\043", app_id_MMSreset           },
    { "\160", "\191\044", app_id_MMSkill            },
    { "\160", "\159\045", app_id_MMSgetProgInvocAttr},
    { "\160", "\191\046", app_id_MMSobtainFile      },
    { "\160", "\191\047", app_id_MMSdefEventCond    },
    { "\160", "\191\048", app_id_MMSdelEventCond    },
    { "\160", "\191\049", app_id_MMSgetEventCondAttr},
    { "\160", "\191\050", app_id_MMSrepEventCondSt  },
    { "\160", "\191\051", app_id_MMSaltEventCondMon },
    { "\160", "\191\052", app_id_MMStriggerEvent    },
    { "\160", "\191\053", app_id_MMSdefEventAction  },
    { "\160", "\191\054", app_id_MMSdelEventAction     },
    { "\160", "\191\055", app_id_MMSgetEventActionAttr },
    { "\160", "\191\056", app_id_MMSrepEventActionSt   },
    { "\160", "\191\057", app_id_MMSdefEventEnrol      },
    { "\160", "\191\058", app_id_MMSdelEventEnrol      },
    { "\160", "\191\059", app_id_MMSaltEventEnrol      },
    { "\160", "\191\060", app_id_MMSrepEventEnrolSt    },
    { "\160", "\191\061", app_id_MMSgetEventEnrolAttr  },
    { "\160", "\191\062", app_id_MMSackEventNot        },
    { "\160", "\191\063", app_id_MMSgetAlarmSum        },
    { "\160", "\191\064", app_id_MMSgetAlarmEnrolSum   },
    { "\160", "\191\065", app_id_MMSreadJournal        },
    { "\160", "\191\066", app_id_MMSwriteJournal       },
    { "\160", "\191\067", app_id_MMSinitJournal        },
    { "\160", "\191\068", app_id_MMSrepJournalSt       },
    { "\160", "\191\069", app_id_MMScrtJournal         },
    { "\160", "\191\070", app_id_MMSdelJournal         },
    { "\160", "\191\071", app_id_MMSgetCapList         },
    { "\160", "\191\072", app_id_MMSfileOpen           },
    { "\160", "\159\073", app_id_MMSfileRead           },
    { "\160", "\159\074", app_id_MMSfileClose          },
    { "\160", "\191\075", app_id_MMSfileRename         },
    { "\160", "\191\076", app_id_MMSfileDelete         },
    { "\160", "\191\077", app_id_MMSfileDir            },
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:inProcessService()
    end
    DC.printf('%s: Inprocess, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    DC.printf('%s: service %d, appId %d\n', DetectorPackageInfo.name, context.service_id,
        context.appId)
    if context.payload_id then
        DC.printf('%s: payload_id %d\n', DetectorPackageInfo.name, context.payload_id)
        gDetector:service_analyzePayload(context.payload_id)
    end
    if not flowFlag or flowFlag == 0 then
        gDetector:addService(context.service_id, "", "", context.appId)
    end
    DC.printf('%s: Detected, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:failService()
    end
    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    for i,v in ipairs(gFastPatterns) do
        if gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0 then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name, v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,
                v[2][1])
        end
    end

    for i,v in ipairs(gAppRegistry) do
        pcall(function () gDetector:registerAppId(v[1],v[2]) end)
    end
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',DetectorPackageInfo.name)
    gDetector:init(DetectorPackageInfo.name, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end

local function scanForCommand(command_index, servreq_index)
    DC.printf('Scanning for command at command index %d, servreq index %d\n', command_index,
        servreq_index)
    for i = 1, #MMSmsgs do
        if gDetector:memcmp(MMSmsgs[i][1], #MMSmsgs[i][1], command_index) == 0 and
           gDetector:memcmp(MMSmsgs[i][2], #MMSmsgs[i][2], servreq_index) == 0 then
            return MMSmsgs[i][3]
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
    local rft = FT.getFlowTracker(flowKey)

    DC.printf('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', DetectorPackageInfo.name,
        context.packetCount, dir, size)

    if not rft then
        rft = FT.addFlowTracker(flowKey, {next_packet = 0, get_client = 0, h245 = 0, 
            src_ip = 0, src_port = 0})
    end

    if size == 0 or (dir == 0 and rft.get_client == 0) then
        return serviceInProcess(context)
    end

    if size >= 6 and DC.checkPattern(gDetector, gPatterns.tpkt) then
        DC.printf('TPKT header\n')

        -- ITU H.245 section
        if rft.h245 == 1 then
            DC.printf('H.245 continue\n')
            if DC.checkPattern(gDetector, gPatterns.open_logical_channel_ack) then
                matched, src_ip_raw, src_port_raw = gDetector:getPcreGroups("(....)(..)",14)
                if matched and gDetector.createFutureFlow then
                    rft.src_ip = DC.reverseBinaryStringToNumber(src_ip_raw, 4)
                    rft.src_port = DC.binaryStringToNumber(src_port_raw, 2)
                    rft.h245 = 2
                    DC.printf('H.245 first open logical channel packet\n')
                end
            end
            context.service_id = apps.h245.svc_id                                                   
            context.appId = apps.h245.app_id
            context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
            return serviceSuccess(context)
        elseif rft.h245 == 2 then
            DC.printf('H.245 looking for second open logical channel packet\n')
            if DC.checkPattern(gDetector, gPatterns.open_logical_channel_ack) then
                matched, dst_ip_raw, dst_port_raw = gDetector:getPcreGroups("(....)(..)",14)
                if matched and gDetector.createFutureFlow then
                    dst_ip = DC.reverseBinaryStringToNumber(dst_ip_raw, 4)
                    dst_port = DC.binaryStringToNumber(dst_port_raw, 2)
                    src_ip_str = DC.intToIPv4(rft.src_ip, 1)
                    dst_ip_str = DC.intToIPv4(dst_ip, 1)
                    DC.printf('creating RTP future flow %s:%d - %s:%d\n', src_ip_str, rft.src_port,
                        dst_ip_str, dst_port)
                    gDetector:createFutureFlow(src_ip_str, rft.src_port, dst_ip_str, dst_port, 17,
                        apps.h245.app_id, apps.h245.app_id, apps.rtp.app_id, apps.rtp.app_id)
                    -- reset to 1 to keep watch for new logical connections
                    rft.h245 = 1
                    rft.src_ip = nil
                    rft.src_port = nil
                end
            end
            -- One H.245 session can open multiple RTP streams, so we will keep continuing.
            context.service_id = apps.h245.svc_id                                                   
            context.appId = apps.h245.app_id
            context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
            return serviceSuccess(context)
        elseif DC.checkPattern(gDetector, gPatterns.h245) then
            DC.printf('H.245 detected\n')
            rft.h245 = 1
            rft.get_client = 1
            context.service_id = apps.h245.svc_id
            context.appId = apps.h245.app_id
            context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
            return serviceSuccess(context)
        end

        -- Other ITU protocols
        matched, fifth_byte_raw, sixth_byte_raw, eighth_byte_raw = gDetector:getPcreGroups("(.)(.).(.)",4)
        fifth_byte = DC.binaryStringToNumber(fifth_byte_raw, 1)
        sixth_byte = DC.binaryStringToNumber(sixth_byte_raw, 1)
        eighth_byte = DC.binaryStringToNumber(eighth_byte_raw, 1)
        if fifth_byte == 8 and sixth_byte == 2 then
            DC.printf('Q.931 header\n')
            if gDetector:getPcreGroups(h225_identifier) then
                DC.printf('H.225 detected (and we assume H.323 is also detected)\n')
                context.service_id = apps.h225.svc_id
                context.appId = apps.h225.app_id
                context.payload_id = apps.h323.app_id
            else
                DC.printf('no other protocol layer identified, it\'s just Q.931\n')
                context.service_id = apps.q931.svc_id
                context.appId = apps.q931.app_id
            end
            return serviceSuccess(context)
        end

        -- ISO section
        if rft.next_packet == 0 and sixth_byte == 208 then
            DC.printf('COTP packet\n')
            rft.next_packet = 1
            return serviceInProcess(context)
        elseif rft.next_packet == 1 then
            if eighth_byte == 114 and gDetector:memcmp(s7commplus_tail, #s7commplus_tail, size - #s7commplus_tail) == 0 then
                DC.printf('got S7CommPlus!\n')
                context.service_id = apps.s7commplus.svc_id
                context.appId = apps.s7commplus.app_id
            elseif sixth_byte == 240 and gDetector:getPcreGroups('\202\034(\002\003|\001\001)') then
                DC.printf('got MMS!\n')
                context.service_id = apps.isomms.svc_id
                context.appId = apps.isomms.app_id
                rft.next_packet = 2
                rft.get_client = 1
                context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
            elseif sixth_byte == 240 and srcPort == 3398 then
                DC.printf('this is RDP\n')
                context.service_id = apps.rdp.svc_id
                context.appId = apps.rdp.app_id
            else
                DC.printf('All we know is this is COTP frame\n')
                context.service_id = apps.cotp.svc_id
                context.appId = apps.cotp.app_id
            end
            return serviceSuccess(context)
        elseif rft.next_packet == 2 then
            DC.printf('analyzing for MMS payload\n')
            if sixth_byte == 240 then
                --[[ to find the command_index, and service_request_index,
                  we need to know the COTP header length (value of byte five, +1)
                  and the invokeId length. Packet structure appears to be
                  TPKT header -> 4 bytes
                  COTP header -> noted in fifth byte, plus one
                  ISO 8327-1 OSI Session Layer Headers -> not sure about these,
                    but there appear to be two of them, each of length 0, +2
                    in our confirmedRequestPDUs
                  ISO 8823 OSI Presentation Layer header -> 9 bytes
                  we also need to figure the index of the presentation-context-identifier
                    (pci is the seventh byte of the ISO 8823 header)
                --]]

                -- check that this is a 'confirmedRequestPDU' - for now
                -- this is all we are looking for. We may or may not
                -- have to open our search to other PDU types later.
                -- check that the first and third bytes of the MMS PDU are both a0
                type_index = fifth_byte + 16
                if size < type_index + 2 then
                    -- bad packet
                    return serviceFail(context)
                end
                type_byte_one_raw = gDetector:getPcreGroups("(.)", type_index)
                type_byte_three_raw = gDetector:getPcreGroups("(.)", type_index + 2)
                type_byte_one = DC.binaryStringToNumber(type_byte_one_raw, 1)
                type_byte_three = DC.binaryStringToNumber(type_byte_three_raw, 1)
                if type_byte_one ~= 160 then
                    context.service_id = apps.isomms.svc_id
                    context.appId = apps.isomms.app_id
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                elseif type_byte_three == 161 then
                    context.service_id = apps.isomms.svc_id
                    context.appId = apps.isomms.app_id
                    context.payload_id = app_id_MMSconfirmedRes
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                elseif type_byte_three == 162 then
                    context.service_id = apps.isomms.svc_id
                    context.appId = apps.isomms.app_id
                    context.payload_id = app_id_MMSconfirmedErr
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                elseif type_byte_three == 163 then
                    context.service_id = apps.isomms.svc_id
                    context.appId = apps.isomms.app_id
                    context.payload_id = app_id_MMSunconfirmed
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                elseif type_byte_three == 160 then
                    context.service_id = apps.isomms.svc_id
                    context.appId = apps.isomms.app_id
                else
                    context.service_id = apps.isomms.svc_id
                    context.appId = apps.isomms.app_id
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                end

                -- compute pci_index and check that the value of that byte is 3
                --   for mms-abstract-syntax-version1
                pci_index = fifth_byte + 15
                if size < pci_index then
                    -- bad packet
                    return serviceFail(context)
                end
                pci_byte_raw = gDetector:getPcreGroups("(.)", pci_index)
                pci_byte = DC.binaryStringToNumber(pci_byte_raw, 1)
                if pci_byte ~= 3 then
                    context.service_id = apps.isomms.svc_id                                             
                    context.appId = apps.isomms.app_id  
                    context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                    return serviceSuccess(context)
                end

                invokeid_len_index = fifth_byte + 21
                if size < invokeid_len_index then
                    -- bad packet
                    return serviceFail(context)
                end
                invokeid_len_raw = gDetector:getPcreGroups("(.)", invokeid_len_index)
                invokeid_len = DC.binaryStringToNumber(invokeid_len_raw, 1)
                DC.printf('invokeid index is %d, len is %d\n', invokeid_len_index, invokeid_len)
                command_index = fifth_byte + 18
                service_request_index = command_index + invokeid_len + 4
                if size < service_request_index then
                    -- bad packet
                    return serviceFail(context)
                end
                commandId = scanForCommand(command_index, service_request_index)
                if commandId then
                    DC.printf('Adding payload %d\n', commandId)
                    context.payload_id = commandId
                end
                context.service_id = apps.isomms.svc_id
                context.appId = apps.isomms.app_id
                context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                return serviceSuccess(context)
            end
        end
        DC.printf('All we know is this is TPKT frame\n')
        context.service_id = apps.tpkt.app_id
        context.appId = apps.tpkt.app_id
        return serviceSuccess(context)
    end

    return serviceFail(context)

end

function DetectorFini()
end
