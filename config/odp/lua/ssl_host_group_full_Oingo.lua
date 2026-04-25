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
detection_name: SSL Group Full "Oingo"
version: 23
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Redbox' => 'Online movie rental and video streaming.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'SoftEther' => 'An open source VPN.',
          'LivePerson' => 'Online Marketing and Web analytics service provider.',
          'Vdio' => 'Web magazine.',
          'Java Update' => 'Java update software service.',
          'Chartbeat' => 'Realtime Website data for Collection.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_Oingo",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Rdio (Deprecated)
	--{ 0, 1029, 'rdio-a.akamaihd.net' },
	--{ 0, 1029, 'rdio.com' },
	--{ 0, 1029, 'rd.io' },
	--Chartbeat
	{ 0, 1460, 'chartbeat.com' },
	--Java Update
	{ 1, 1569, 'javadl-esd-secure.oracle.com' },
	--LivePerson
	{ 0, 1797, 'liveperson.com' },
	--EdgeCast (Deprecated)
	--{ 0, 1821, 'edgecastcdn.net' },
	--Vdio
	{ 0, 1829, 'vdio-a.akamaihd.net' },
	--Redbox
	{ 0, 1830, 'redbox.ojrq.net' },
	{ 0, 1830, 'redbox.tt.omtrdc.net' },
	--SoftEther
	{ 1, 3809, 'softsether.org' },
	--Habbo
	{ 0, 980, 'habboo-a.akamaihd.net' },
}
function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end
    return gDetector
end

function DetectorClean()
end
