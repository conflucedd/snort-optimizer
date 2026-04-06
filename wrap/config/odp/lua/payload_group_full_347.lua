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
detection_name: Payload Group Full "347"
version: 4
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'ups.com' => 'United Parcel service is the largest package delivery company.',
          'Zscaler' => 'Cloud-based information security.',
          'Wowhead' => 'Website intended to provide World of Warcraft players with tools to make their gameplay more enjoyable.',
          'Liputan 6' => 'Television news program on SCTV, an Indonesian TV station.',
          'CimaClub' => 'Movie and video streaming website.',
          'Coolmath' => 'Educational games portal.',
          'iflix' => 'Movie streaming.',
          'Wirtualna Polska' => 'Polish news webportal.',
          'wikiHow' => 'Online guide for how to do anything.',
          'Upwork' => 'Global freelancing platform for businesses and independent professionals be connected.',
          'Stile' => 'Online educational platform.',
          'Drift' => 'Conversational marketing platform.',
          'weblio' => 'Online Japnese-English dictionary.',
          'WIX' => 'Cloud-based web development platform.',
          'MawDoo3' => 'Arabic online encyclopedia.',
          'VICE' => 'Official website for VICE magazine, which focus on arts, culture and news topics.',
          'Catholic Education Australia' => 'Site for Catholic Schools and to the schools in the Archdiocese of Canberra and Goulburn.',
          'Udemy' => 'Online site for learning and teaching for students.',
          'Xcar' => 'A Chinese automotive news website.',
          'Uptodown' => 'Mobile app for downloading software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_347",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Liputan 6
	{ 0, 0, 0, 2031, 1, "liputan6.id", "/", "http:", "", 4350 },
	{ 0, 0, 0, 2031, 1, "one.co.id", "/", "http:", "", 4350 },
	--Udemy
	{ 0, 0, 0, 2016, 1, "udemycdn.com", "/", "http:", "", 4353 },
	{ 0, 0, 0, 2016, 1, "udemymail.com", "/", "http:", "", 4353 },
	--ups.com
	{ 0, 0, 0, 2028, 1, "ups.inq.com", "/", "http:", "", 4356 },
	--Uptodown
	{ 0, 0, 0, 2027, 1, "uptodown.io", "/", "http:", "", 4357 },
	{ 0, 0, 0, 2027, 1, "uptodown.zendesk.com", "/", "http:", "", 4357 },
	{ 0, 0, 0, 2027, 1, "utdstc.com", "/", "http:", "", 4357 },
	--Upwork
	{ 0, 0, 0, 2026, 1, "static-upwork.com", "/", "http:", "", 4358 },
	--VICE
	{ 0, 0, 0, 2022, 1, "vicetv.com", "/", "http:", "", 4362 },
	--weblio
	{ 0, 0, 0, 2020, 1, "weblio.hs.llnwd.net", "/", "http:", "", 4365 },
	--wikiHow
	{ 0, 0, 0, 2017, 1, "wikihow.cz", "/", "http:", "", 4368 },
	{ 0, 0, 0, 2017, 1, "wikihow.it", "/", "http:", "", 4368 },
	{ 0, 0, 0, 2017, 1, "wikihow.com.tr", "/", "http:", "", 4368 },
	{ 0, 0, 0, 2017, 1, "wikihow.vn", "/", "http:", "", 4368 },
	{ 0, 0, 0, 2017, 1, "wikihowfarsi.com", "/", "http:", "", 4368 },
	--Wirtualna Polska
	{ 0, 0, 0, 2015, 1, "wp.hit.gemius.pl", "/", "http:", "", 4369 },
	{ 0, 0, 0, 2015, 1, "wpimg.pl", "/", "http:", "", 4369 },
	{ 0, 0, 0, 2015, 1, "wpcdn.pl", "/", "http:", "", 4369 },
	--WIX
	{ 0, 0, 0, 2014, 1, "wixstatic.com", "/", "http:", "", 4371 },
	--Wowhead
	{ 0, 0, 0, 2013, 1, "wow.zamimg.com", "/", "http:", "", 4372 },
	--Xcar
	{ 0, 0, 0, 2012, 1, "xcarimg.com", "/", "http:", "", 4375 },
	--iflix
	{ 0, 0, 0, 2009, 1, "wetvinfo.com", "/", "http:", "", 4526 },
	--CimaClub
	{ 0, 0, 0, 2008, 1, "cimaclub.club", "/", "http:", "", 4534 },
	--MawDoo3
	{ 0, 0, 0, 2006, 1, "modo3.com", "/", "http:", "", 4536 },
	--Coolmath
	{ 0, 0, 0, 2001, 1, "coolmath4kids.com", "/", "http:", "", 4587 },
	{ 0, 0, 0, 2001, 1, "coolmathgames.com", "/", "http:", "", 4587 },
	--Drift
	{ 0, 0, 0, 1999, 1, "driftcdn.com", "/", "http:", "", 4589 },
	--Zscaler
	{ 0, 0, 0, 1997, 1, "zscaler.net", "/", "http:", "", 4592 },
	{ 0, 0, 0, 1997, 1, "zscalerone.net", "/", "http:", "", 4592 },
	{ 0, 0, 0, 1997, 1, "zscalertwo.net", "/", "http:", "", 4592 },
	{ 0, 0, 0, 1997, 1, "zscalerthree.net", "/", "http:", "", 4592 },
	{ 0, 0, 0, 1997, 1, "zscalerbeta.net", "/", "http:", "", 4592 },
	{ 0, 0, 0, 1997, 1, "zscloud.net", "/", "http:", "", 4592 },
	--Stile
	{ 0, 0, 0, 1996, 1, "stileapp.com", "/", "http:", "", 4593 },
	--Catholic Education Australia
	{ 0, 0, 0, 1995, 1, "cg.catholic.edu.au", "/", "http:", "", 4595 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
