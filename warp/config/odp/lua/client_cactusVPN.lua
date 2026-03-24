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
detection_name: CactusVPN
version: 3
description: A VPN client.
bundle_description: $VAR1 = {
          'CactusVPN' => 'A VPN client.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "client_cactusVPN",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        fini = 'DetectorFini',
        minimum_matches = 1,
    }
}

gHostPortAppList = {
    { 1, 4139, "192.157.250.58", 443, DC.ipproto.tcp},
    { 1, 4139, "69.197.143.178", 443, DC.ipproto.tcp},
    { 1, 4139, "192.96.205.161", 443, DC.ipproto.tcp},
    { 1, 4139, "104.250.122.130", 443, DC.ipproto.tcp},
    { 1, 4139, "109.169.19.90", 443, DC.ipproto.tcp},
    { 1, 4139, "109.169.22.71", 443, DC.ipproto.tcp},
    { 1, 4139, "109.169.19.89", 443, DC.ipproto.tcp},
    { 1, 4139, "212.48.93.19", 443, DC.ipproto.tcp},
    { 1, 4139, "88.150.154.46", 443, DC.ipproto.tcp},
    { 1, 4139, "130.185.151.178", 443, DC.ipproto.tcp},
    { 1, 4139, "195.154.189.165", 443, DC.ipproto.tcp},
    { 1, 4139, "88.198.133.4", 443, DC.ipproto.tcp},
    { 1, 4139, "158.69.26.89", 443, DC.ipproto.tcp},
    { 1, 4139, "95.211.146.164", 443, DC.ipproto.tcp},
    { 1, 4139, "95.211.174.144", 443, DC.ipproto.tcp},
    { 1, 4139, "95.211.186.158", 443, DC.ipproto.tcp},
    { 1, 4139, "62.212.85.102", 443, DC.ipproto.tcp},
    { 1, 4139, "93.115.92.240", 443, DC.ipproto.tcp},
    { 1, 4139, "176.126.252.72", 443, DC.ipproto.tcp},

    { 1, 4139, "192.157.250.58", 1723, DC.ipproto.tcp},
    { 1, 4139, "69.197.143.178", 1723, DC.ipproto.tcp},
    { 1, 4139, "192.96.205.161", 1723, DC.ipproto.tcp},
    { 1, 4139, "104.250.122.130", 1723, DC.ipproto.tcp},
    { 1, 4139, "109.169.19.90", 1723, DC.ipproto.tcp},
    { 1, 4139, "109.169.22.71", 1723, DC.ipproto.tcp},
    { 1, 4139, "109.169.19.89", 1723, DC.ipproto.tcp},
    { 1, 4139, "212.48.93.19", 1723, DC.ipproto.tcp},
    { 1, 4139, "88.150.154.46", 1723, DC.ipproto.tcp},
    { 1, 4139, "130.185.151.178", 1723, DC.ipproto.tcp},
    { 1, 4139, "195.154.189.165", 1723, DC.ipproto.tcp},
    { 1, 4139, "88.198.133.4", 1723, DC.ipproto.tcp},
    { 1, 4139, "158.69.26.89", 1723, DC.ipproto.tcp},
    { 1, 4139, "95.211.146.164", 1723, DC.ipproto.tcp},
    { 1, 4139, "95.211.174.144", 1723, DC.ipproto.tcp},
    { 1, 4139, "95.211.186.158", 1723, DC.ipproto.tcp},
    { 1, 4139, "62.212.85.102", 1723, DC.ipproto.tcp},
    { 1, 4139, "93.115.92.240", 1723, DC.ipproto.tcp},
    { 1, 4139, "176.126.252.72", 1723, DC.ipproto.tcp},
}

gSSLHostPatternList = {

    { 1, 4139, 'cactusdb.net' },
    { 1, 4139, 'cactusvpn.com' },
    { 1, 4139, 'cactussstp.com' },

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    DC.printf("client_cactusVPN: addinging ssl patterns and hostport entries\n")

    if gDetector.addHostPortApp then
        for i,v in ipairs(gHostPortAppList) do
            gDetector:addHostPortApp(v[1],v[2],v[3],v[4],v[5])
        end
    end

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector
end

function DetectorClean()
end

function DetectorFini()
end
