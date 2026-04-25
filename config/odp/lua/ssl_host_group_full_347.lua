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
detection_name: SSL Group Full "347"
version: 4
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Liputan 6' => 'Television news program on SCTV, an Indonesian TV station.',
          'Coolmath' => 'Educational games portal.',
          'VICE' => 'Official website for VICE magazine, which focus on arts, culture and news topics.',
          'Catholic Education Australia' => 'Site for Catholic Schools and to the schools in the Archdiocese of Canberra and Goulburn.',
          'wikiHow' => 'Online guide for how to do anything.',
          'ups.com' => 'United Parcel service is the largest package delivery company.',
          'Stile' => 'Online educational platform.',
          'weblio' => 'Online Japnese-English dictionary.',
          'Zscaler' => 'Cloud-based information security.',
          'Wowhead' => 'Website intended to provide World of Warcraft players with tools to make their gameplay more enjoyable.',
          'Upwork' => 'Global freelancing platform for businesses and independent professionals be connected.',
          'Udemy' => 'Online site for learning and teaching for students.',
          'Uptodown' => 'Mobile app for downloading software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_347",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Liputan 6
	{ 0, 4350, 'liputan6.id' },
	{ 0, 4350, 'one.co.id' },
	--Udemy
	{ 0, 4353, 'udemycdn.com' },
	{ 0, 4353, 'udemymail.com' },
	--ups.com
	{ 0, 4356, 'ups.inq.com' },
	--Uptodown
	{ 0, 4357, 'uptodown.io' },
	{ 0, 4357, 'uptodown.zendesk.com' },
	{ 0, 4357, 'utdstc.com' },
	--Upwork
	{ 0, 4358, 'static-upwork.com' },
	--VICE
	{ 0, 4362, 'vicetv.com' },
	--weblio
	{ 0, 4365, 'weblio.hs.llnwd.net' },
	--wikiHow
	{ 0, 4368, 'wikihow.cz' },
	{ 0, 4368, 'wikihow.it' },
	{ 0, 4368, 'wikihow.com.tr' },
	{ 0, 4368, 'wikihow.vn' },
	{ 0, 4368, 'wikihowfarsi.com' },
	--Wowhead
	{ 0, 4372, 'wow.zamimg.com' },
	--Coolmath
	{ 0, 4587, 'coolmath4kids.com' },
	{ 0, 4587, 'coolmathgames.com' },
	--Zscaler
	{ 0, 4592, 'zscaler.net' },
	{ 0, 4592, 'zscalerone.net' },
	{ 0, 4592, 'zscalertwo.net' },
	{ 0, 4592, 'zscalerthree.net' },
	{ 0, 4592, 'zscalerbeta.net' },
	{ 0, 4592, 'zscloud.net' },
	--Stile
	{ 0, 4593, 'stileeducation.com' },
	--Catholic Education Australia
	{ 0, 4595, 'cg.catholic.edu.au' },
}
gSSLCnamePatternList = {
	--Liputan 6
	{ 0, 4350, 'liputan6.id' },
	--ups.com
	{ 0, 4356, 'ups.inq.com' },
	--Uptodown
	{ 0, 4357, 'uptodown.io' },
	{ 0, 4357, 'uptodown.zendesk.com' },
	--VICE
	{ 0, 4362, 'vicetv.com' },
	--wikiHow
	{ 0, 4368, 'wikihow.cz' },
	{ 0, 4368, 'wikihow.it' },
	{ 0, 4368, 'wikihow.com.tr' },
	{ 0, 4368, 'wikihow.vn' },
	{ 0, 4368, 'wikihowfarsi.com' },
	--Wowhead
	{ 0, 4372, 'wow.zamimg.com' },
	--Coolmath
	{ 0, 4587, 'coolmath4kids.com' },
	{ 0, 4587, 'coolmathgames.com' },
	--Zscaler
	{ 0, 4592, 'zscaler.net' },
	{ 0, 4592, 'zscalerone.net' },
	{ 0, 4592, 'zscalertwo.net' },
	{ 0, 4592, 'zscalerthree.net' },
	{ 0, 4592, 'zscalerbeta.net' },
	{ 0, 4592, 'zscloud.net' },
	--Stile
	{ 0, 4593, 'stileeducation.com' },
	--Catholic Education Australia
	{ 0, 4595, 'cg.catholic.edu.au' },
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
