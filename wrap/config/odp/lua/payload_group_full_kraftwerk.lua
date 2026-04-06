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
detection_name: Payload Group Full "Kraftwerk"
version: 41
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Ubuntu Update Manager' => 'Update manager.',
          'AT&T' => 'Telecom and Internet provider.',
          'TED' => 'Conference and Talk show to share ideas.',
          'Nokia Maps' => 'Nokia mapping and directions service.',
          'ESPN' => 'Online Sports news and show.',
          'BBC' => 'Web Portal for news update.',
          'Conduit' => 'Online website to create community toolbar.',
          'Fox News' => 'Web Portal for news update.',
          'Wall Street Journal' => 'Web Portal for news update.',
          'WeatherBug' => 'Windows weather application.',
          'The Huffington Post' => 'Online news website.',
          'Wolfram Alpha' => 'Online answering for queries from the structred data.',
          'Comcast' => 'Web Portal.',
          'Eclipse Marketplace' => 'Marketplace for Eclipse application.',
          'Verizon Wireless' => 'Telecom and Internet provider.',
          'AOL' => 'American company develops, grows and invests in brands and web sites.',
          'Amazon Web Services' => 'Online cloud computing service.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_kraftwerk",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--ESPN
	{ 0, 0, 0, 526, 22, "espncdn.com", "/", "http:", "", 1364 },
	{ 0, 0, 0, 526, 22, "espnfc", "/", "http:", "", 1364 },
	--Comcast
	{ 0, 0, 0, 527, 22, "comcast.net", "/", "http:", "", 1365 },
	--Fox News
	{ 0, 0, 0, 528, 22, "foxnews.demdex.net", "/", "http:", "", 1366 },
	{ 0, 0, 0, 528, 22, "foxnews.mobi", "/", "http:", "", 1366 },
	{ 0, 0, 0, 528, 22, "fncstatic.com", "/", "http:", "", 1366 },
	{ 0, 0, 0, 528, 22, "foxnews-f.akamaihd.net", "/", "http:", "", 1366 },
	--Weather.com
	--{ 0, 0, 0, 529, 22, "weather.com", "/", "http:", "", 1367 },
	--The Huffington Post
	{ 0, 0, 0, 532, 33, "huffingtonpost.co.uk", "/", "http:", "", 1370 },
	{ 0, 0, 0, 532, 33, "huffpost.com", "/", "http:", "", 1370 },
	--Conduit
	{ 0, 0, 0, 537, 22, "como.com", "/", "http:", "", 1375 },
	{ 0, 0, 0, 537, 22, "getu.com", "/", "http:", "", 1375 },
	--BBC
	{ 0, 0, 0, 538, 33, "bbci.co.uk", "/", "http:", "", 1376 },
	{ 0, 0, 0, 538, 33, "bbc.com", "/", "http:", "", 1376 },
	{ 0, 0, 0, 538, 33, "bbcamerica.com", "/", "http:", "", 1376 },
	{ 0, 0, 0, 538, 33, "bbccanada.com", "/", "http:", "", 1376 },
	{ 0, 0, 0, 538, 33, "cbeebies.com", "/", "http:", "", 1376 },
	{ 0, 0, 0, 538, 33, "feeds.bbci.co.uk", "/", "http:", "", 1376 },
	--AT&T
	{ 0, 0, 0, 542, 22, "att.net", "/", "http:", "", 1380 },
	--Search-Result.com (Deprecated)
	--{ 0, 0, 0, 546, 22, "search-result.com", "/", "http:", "", 1384 },
	--Verizon Wireless
	{ 0, 0, 0, 550, 22, "vzw.com", "/", "http:", "", 1388 },
	{ 0, 0, 0, 550, 22, "myvzw.com", "/", "http:", "", 1388 },
	--ABC
	--{ 0, 0, 0, 551, 33, "abcnews.go.com", "/", "http:", "", 1389 },
	--{ 0, 0, 0, 551, 33, "abcnews.com", "/", "http:", "", 1389 },
	--{ 0, 0, 0, 551, 33, "abc.go.com", "/", "http:", "", 1389 },
	--{ 0, 0, 0, 551, 33, "abc.com", "/", "http:", "", 1389 },
	--Wall Street Journal
	{ 0, 0, 0, 552, 33, "wsj.net", "/", "http:", "", 1390 },
	{ 0, 0, 0, 552, 33, "marketwatch.com", "/", "http:", "", 1390 },
	{ 0, 0, 0, 552, 33, "barrons.com", "/", "http:", "", 1390 },
	{ 0, 0, 0, 552, 33, "smartmoney.com", "/", "http:", "", 1390 },
	{ 0, 0, 0, 552, 33, "allthingsd.com", "/", "http:", "", 1390 },
	{ 0, 0, 0, 552, 33, "fins.com", "/", "http:", "", 1390 },
	{ 0, 0, 0, 552, 33, "wsjradio.com", "/", "http:", "", 1390 },
	--Amazon Web Services
	{ 0, 0, 0, 554, 22, "aws.amazon.com", "/", "http:", "", 1392 },
	--Me.com (Deprecated)
	--{ 0, 0, 0, 556, 22, "me.com", "/", "http:", "", 1394 },
	--TED
	{ 0, 0, 0, 565, 33, "tedhls-vod.hls.adaptive.level3.net", "/", "http:", "", 1403 },
	--Ubuntu Update Manager
	{ 0, 0, 0, 568, 22, "archive.ubuntu.com", "/", "http:", "", 1409 },
	--Eclipse Marketplace
	{ 0, 0, 0, 570, 22, "marketplace.eclipse.org", "/", "http:", "", 1414 },
	--AOL
	{ 0, 0, 0, 574, 22, "aol.co.uk", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aolcdn.com", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.sg", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.ca", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.de", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.in", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.fr", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.ch", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.ie", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.jp", "/", "http:", "", 1419 },
	{ 0, 0, 0, 574, 22, "aol.it", "/", "http:", "", 1419 },
	--WeatherBug
	{ 0, 0, 0, 577, 22, "wxbug.com", "/", "http:", "", 1421 },
	--Microsoft
	--{ 0, 0, 0, 579, 22, "msftncsi.com", "/", "http:", "", 1423 },
	--Nokia Maps
	{ 0, 0, 0, 583, 22, "maps.nokia.com", "/", "http:", "", 1427 },
	{ 0, 0, 0, 583, 22, "here.com", "/", "http:", "", 1427 },
	--{ 0, 0, 0, 583, 22, "here.sc", "/", "http:", "", 1427 },
	--Wolfram Alpha
	{ 0, 0, 0, 585, 22, "wolframcdn.com", "/", "http:", "", 1429 },
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
