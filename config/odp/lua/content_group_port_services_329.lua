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
detection_name: Content Group "Port Services 329"
version: 4
description: Group of Port Service detectors.
bundle_description: $VAR1 = {
          'FLN-SPX' => 'Berkeley rlogind with SPX auth registered with IANA on port 221 TCP/UDP.',
          'SQLSRV' => 'SQL Service registered with IANA on port 156 TCP/UDP.',
          'SQL-NET' => 'SQL-Net (or Net8) is a networking software developed by Oracle. It allows remote data-access between programs and the Oracle Database.',
          'NETSC-DEV' => 'NETSC registered with IANA on port 155 TCP/UDP.',
          'DMP' => 'Direct Message Protocol. UDP 5031.',
          'UUCP-PATH' => 'Path Service is used determine mailbox addresses for hosts that are not part of the ARPA-Internet.',
          'Tivoli Object Dispatcher' => 'A part of IBM\'s Tivoli suite. TCP/UDP 94.',
          'Dameware' => 'Remote desktop software suite.',
          'LEGENT-2' => 'Legent Corporation registered with IANA on port 374 TCP/UDP.',
          'EMFIS-CNTL' => 'EMFIS Control Service registered with IANA on port 141 TCP/UDP.',
          'dls-mon' => 'Directory Location Service Monitor registered with IANA on port 198 TCP/UDP.',
          'ORBIX-CFG-SSL' => 'Orbix is a CORBA (Object Request Broker) Orbix cfg (config) works over SSL typically on port 3078.',
          'MATIP-TYPE-B' => 'Mapping of Airline Traffic over IP Type B (MATIP) is an e-mail application where real-time is not needed registered with IANA on port 351 TCP/UDP.',
          'DN6-NLM-AUD' => 'DNSIX Network Level Module Audit registered with IANA on port 195 TCP/UDP.',
          'CoAP' => 'Constrained Application Protocol, for IoT devices. TCP/UDP 5683.',
          'UUCP-RLOGIN' => 'Rlogin is a part of UUCP (Unix-to-Unix Copy) a suite of computer programs and protocols.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_port_services_329",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "AppId", "port", "protocol" (6 = TCP, 17 = UDP)
gPortServiceList = {

    -- CoAP
    {7345, 5683, 6},
    {7345, 5683, 17},
    -- Tivoli Object Dispatcher
    {7344, 94, 6},
    {7344, 94, 17},
    -- DMP
    {7347, 5031, 17},
    -- dls-mon
    {4570, 198, 6},
    {4570, 198, 17},
    -- DN6-NLM-AUD
    {4571, 195, 6},
    {4571, 195, 17},
    -- EMFIS-CNTL
    {4572, 141, 6},
    {4572, 141, 17},
    -- FLN-SPX
    {4573, 221, 6},
    {4573, 221, 17},
    -- LEGENT-2
    {4574, 374, 6},
    {4574, 374, 17},
    -- MATIP-TYPE-B
    {4575, 351, 6},
    {4575, 351, 17},
    -- NETSC-DEV
    {4576, 155, 6},
    {4576, 155, 17},
    -- ORBIX-CFG-SSL
    {4577, 3078, 6},
    {4577, 3078, 17},
    -- SQL-NET
    {4578, 150, 6},
    {4578, 150, 17},
    -- SQLSRV
    {4579, 156, 6},
    {4579, 156, 17},
    -- UUCP-PATH
    {4580, 117, 6},
    {4580, 117, 17},
    -- UUCP-RLOGIN
    {4581, 541, 6},
    {4581, 541, 17},
    -- Dameware
    {4902, 6129, 6},
    {4902, 6130, 6},
    {4902, 6132, 6},
    {4902, 6133, 6},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.portOnlyService then
        for i,v in ipairs(gPortServiceList) do
            gDetector:portOnlyService(v[1], v[2], v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
