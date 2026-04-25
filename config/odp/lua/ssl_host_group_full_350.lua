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
detection_name: SSL Group Full "350"
version: 21
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'GREE Games' => 'A Japanese social network and mobile gaming site.',
          'Putlocker' => 'Online file hosting service.',
          'MSN' => 'Portal for news, video, and other content.',
          'ShowDocument' => 'Web application that allows users to collaborate on and review documents in real time.',
          'Hightail' => 'Secure file transfer service. Formerly Yousendit.',
          'Proclivity' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_350",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--TurboUpload (Deprecated)
	--{ 0, 1017, 'turboupload.com' },
	--Putlocker
	{ 0, 1224, 'putlocker.is' },
	--Burstly (Deprecated)
	--{ 0, 1312, 'appads.com.w3snoop.com' },
	--CanvasRider
	--{ 0, 1361, 'canvasrider.com' },
	--Search-Result.com (Deprecated)
	--{ 0, 1384, 'search-result.com' },
	--2Leep (Deprecated)
	--{ 0, 1781, '2leep.com' },
	--HLN (Deprecated)
	--{ 0, 2254, 'hlntv.com' },
	--Realview TV (Deprecated)
	--{ 0, 2439, 'realviewtv.com' },
	--Media Innovation Group (Deprecated)
	--{ 0, 2523, 'mookie1.com' },
	--Proclivity
	{ 0, 2533, 't.pswec.com' },
	--MSN
	{ 0, 308, 'msn.co.uk' },
	--GREE Games
	{ 0, 3852, 'gree.jp' },
	--ShowDocument
	{ 0, 831, 'showdocument.net' },
	--Hightail
	{ 0, 928, 'hightail.com' },
}
gSSLCnamePatternList = {
	--TurboUpload (Deprecated)
	--{ 0, 1017, 'turboupload.com' },
	--Putlocker
	{ 0, 1224, 'putlocker.is' },
	--Burstly (Deprecated)
	--{ 0, 1312, 'appads.com.w3snoop.com' },
	--Search-Result.com (Deprecated)
	--{ 0, 1384, 'search-result.com' },
	--2Leep (Deprecated)
	--{ 0, 1781, '2leep.com' },
	--HLN (Deprecated)
	--{ 0, 2254, 'hlntv.com' },
	--Realview TV (Deprecated)
	--{ 0, 2439, 'realviewtv.com' },
	--Media Innovation Group (Deprecated)
	--{ 0, 2523, 'mookie1.com' },
	--MSN
	{ 0, 308, 'msn.co.uk' },
	--GREE Games
	{ 0, 3852, 'gree.jp' },
	--ShowDocument
	{ 0, 831, 'showdocument.net' },
	--Hightail
	{ 0, 928, 'hightail.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3])
        end
    end

    return gDetector
end

function DetectorClean()
end
