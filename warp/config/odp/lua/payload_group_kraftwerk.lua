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
detection_name: Payload Group "Kraftwerk"
version: 40
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'TED' => 'Conference and Talk show to share ideas.',
          'AT&T' => 'Telecom and Internet provider.',
          'TweetDeck' => 'Dashboard application to manage both Twitter and Facebook.',
          'Localytics' => 'Mobile application analytics.',
          'Ubuntu Software Center' => 'Ubuntu software updates.',
          'AdNetwork.net' => 'Ad Portal.',
          'Taobao' => 'Chinese online auction and shopping website.',
          'NASA' => 'Web portal for NASA.',
          'Flipboard' => 'News aggregator Mobile application.',
          'Crazy Browser' => 'A web browser.',
          'Comcast' => 'Web Portal.',
          'ESPN' => 'Online Sports news and show.',
          'Aweber' => 'Email marketing Service.',
          'CanvasRider' => 'Online game website.',
          'Indeed' => 'The job search engine.',
          'Flurry Analytics' => 'Mobile application analytics.',
          'Browzar' => 'A web browser.',
          'Engadget' => 'E-commerce for gadgets and electronics.',
          'RoadRunner' => 'Web Portal for entertainment and sports news update.',
          'Eclipse Updates' => 'Software Updates for Eclipse.',
          'GreenBrowser' => 'A web browser.',
          'Verizon Wireless' => 'Telecom and Internet provider.',
          'Microsoft' => 'Official Microsoft website.',
          'PaleMoon' => 'A web browser.',
          'NOAA' => 'Ocean and Atmospheric research agency.',
          'Amazon Web Services' => 'Online cloud computing service.',
          'Searchnu' => 'Search engine.',
          'Fox News' => 'Web Portal for news update.',
          'Ask.com' => 'Search engine.',
          'OptMD' => 'Web advertisement services.',
          'Wyzo' => 'A web browser.',
          'eHow' => 'Website featuring tutorials on a wide variety of subjects.',
          'Comodo Dragon' => 'A web browser.',
          'Google Adsense' => 'Provides a way for website owners to earn money from their online content.',
          'FC2' => 'Web server, sites and Blog provider.',
          'CloudFront' => 'Content Delivery for AWS.',
          'Planetarium' => 'Planetarium for the Chrome browser.',
          'Sourcefire.com' => 'Company website for Network security and Intrusion Detection engine.',
          'Fox Sports' => 'Web Portal for Sports news update.',
          'NATO' => 'Web portal for NATO.',
          'BBC' => 'Web Portal for news update.',
          'GoDaddy' => 'Domain registrar.',
          'Daily Mail' => 'Web Portal for news update.',
          'WeatherBug' => 'Windows weather application.',
          'Drudge Report' => 'News aggregator.',
          'Wall Street Journal' => 'Web Portal for news update.',
          'Pandora Audio' => 'Online Audio streaming.',
          'Weather.gov' => 'Weather web portal.',
          'Outbrain' => 'Online help for publishers and bloggers.',
          'Nokia Maps' => 'Nokia mapping and directions service.',
          'Conduit' => 'Online website to create community toolbar.',
          'AOL' => 'American company develops, grows and invests in brands and web sites.',
          'ZEDO' => 'Web advertisement services.',
          'Official Major League Baseball' => 'Web Portal for Sports news update.',
          'Etsy' => 'E-commerce website for homemade or vintage items.',
          'The Huffington Post' => 'Online news website.',
          'Wolfram Alpha' => 'Online answering for queries from the structred data.',
          'Arora' => 'A web browser.',
          'SymantecUpdates' => 'Software updates for Symantec.',
          'CometBird' => 'A web browser.',
          'Publishers Clearing House' => 'Online marketing company.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_kraftwerk",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--TweetDeck
	{ 0, 0, 0, 522, 22, "tweetdeck.com", "/", "http:", "", 1360 },
	--CanvasRider
	{ 0, 0, 0, 523, 20, "canvasrider.com", "/", "http:", "", 1361 },
	--ZEDO
	{ 0, 0, 0, 524, 16, "zedo.com", "/", "http:", "", 1362 },
	--eHow
	{ 0, 0, 0, 525, 22, "ehow.com", "/", "http:", "", 1363 },
	--ESPN
	{ 0, 0, 0, 526, 22, "espn.go.com", "/", "http:", "", 1364 },
	--Comcast
	{ 0, 0, 0, 527, 22, "comcast.com", "/", "http:", "", 1365 },
	--Fox News
	{ 0, 0, 0, 528, 22, "foxnews.com", "/", "http:", "", 1366 },
	--Weather.gov
	{ 0, 0, 0, 530, 22, "weather.gov", "/", "http:", "", 1368 },
	--Outbrain
	{ 0, 0, 0, 531, 22, "outbrain.com", "/", "http:", "", 1369 },
	--The Huffington Post
	{ 0, 0, 0, 532, 33, "huffingtonpost.com", "/", "http:", "", 1370 },
	--Ask.com
	{ 0, 0, 0, 533, 22, "ask.com", "/", "http:", "", 1371 },
	--OptMD
	{ 0, 0, 0, 534, 22, "optmd.com", "/", "http:", "", 1372 },
	--GoDaddy
	{ 0, 0, 0, 535, 22, "godaddy.com", "/", "http:", "", 1373 },
	--Etsy
	{ 0, 0, 0, 536, 15, "etsy.com", "/", "http:", "", 1374 },
	--Conduit
	{ 0, 0, 0, 537, 22, "conduit.com", "/", "http:", "", 1375 },
	--BBC
	{ 0, 0, 0, 538, 33, "bbc.co.uk", "/", "http:", "", 1376 },
	--Indeed
	{ 0, 0, 0, 540, 22, "indeed.com", "/", "http:", "", 1378 },
	--Publishers Clearing House
	{ 0, 0, 0, 541, 22, "pch.com", "/", "http:", "", 1379 },
	--AT&T
	{ 0, 0, 0, 542, 22, "att.com", "/", "http:", "", 1380 },
	--Aweber
	{ 0, 0, 0, 543, 22, "aweber.com", "/", "http:", "", 1381 },
	--Fox Sports
	{ 0, 0, 0, 544, 22, "foxsports.com", "/", "http:", "", 1382 },
	--Searchnu
	{ 0, 0, 0, 545, 22, "searchnu.com", "/", "http:", "", 1383 },
	--Official Major League Baseball
	{ 0, 0, 0, 547, 22, "mlb.com", "/", "http:", "", 1385 },
	--RoadRunner
	{ 0, 0, 0, 548, 22, "rr.com", "/", "http:", "", 1386 },
	--Drudge Report
	{ 0, 0, 0, 549, 33, "drudgereport.com", "/", "http:", "", 1387 },
	--Verizon Wireless
	{ 0, 0, 0, 550, 22, "verizonwireless.com", "/", "http:", "", 1388 },
	--Wall Street Journal
	{ 0, 0, 0, 552, 33, "wsj.com", "/", "http:", "", 1390 },
	--Daily Mail
	{ 0, 0, 0, 553, 33, "dailymail.co.uk", "/", "http:", "", 1391 },
	--Amazon Web Services
	{ 0, 0, 0, 554, 22, "amazonaws.com", "/", "http:", "", 1392 },
	--CloudFront
	{ 0, 0, 0, 555, 22, "cloudfront.net", "/", "http:", "", 1393 },
	--Sourcefire.com
	{ 0, 0, 0, 560, 22, "sourcefire.com", "/", "http:", "", 1398 },
	--Taobao
	{ 0, 0, 0, 561, 22, "taobao.com", "/", "http:", "", 1399 },
	--Planetarium
	{ 0, 0, 0, 562, 22, "neave.com", "/planetarium/app/", "http:", "", 1400 },
	--Engadget
	{ 0, 0, 0, 563, 22, "engadget.com", "/", "http:", "", 1401 },
	--Flipboard
	{ 0, 0, 0, 564, 33, "flipboard.com", "/", "http:", "", 1402 },
	--TED
	{ 0, 0, 0, 565, 33, "ted.com", "/", "http:", "", 1403 },
	--Flurry Analytics
	{ 0, 0, 0, 566, 22, "flurry.com", "/", "http:", "", 1406 },
	--Ubuntu Software Center
	{ 0, 0, 0, 567, 22, "software-center.ubuntu.com", "/", "http:", "", 1408 },
	--Eclipse Updates
	{ 0, 0, 0, 569, 22, "download.eclipse.org", "/", "http:", "", 1412 },
	--NASA
	{ 0, 0, 0, 572, 22, "nasa.gov", "/", "http:", "", 1417 },
	--NATO
	{ 0, 0, 0, 573, 22, "nato.int", "/", "http:", "", 1418 },
	--AOL
	{ 0, 0, 0, 574, 22, "aol.com", "/", "http:", "", 1419 },
	--NOAA
	{ 0, 0, 0, 576, 22, "noaa.gov", "/", "http:", "", 1420 },
	--WeatherBug
	{ 0, 0, 0, 577, 22, "weatherbug.com", "/", "http:", "", 1421 },
	--FC2
	{ 0, 0, 0, 578, 22, "fc2.com", "/", "http:", "", 1422 },
	--Microsoft
	{ 0, 0, 0, 579, 22, "microsoft.com", "/", "http:", "", 1423 },
	--Google Adsense
	{ 0, 0, 0, 580, 22, "googlesyndication.com", "/", "http:", "", 1424 },
	--AdNetwork.net
	{ 0, 0, 0, 581, 22, "adnetwork.net", "/", "http:", "", 1425 },
	--Localytics
	{ 0, 0, 0, 582, 22, "localytics.com", "/", "http:", "", 1426 },
	--Nokia Maps
	{ 0, 0, 0, 583, 22, "ovi.com", "/", "http:", "", 1427 },
	{ 0, 0, 0, 583, 22, "maps.nlp.nokia.com", "/", "http:", "", 1427 },
	--SymantecUpdates
	{ 0, 0, 0, 584, 22, "symantecliveupdate.com", "/", "http:", "", 1428 },
	--Wolfram Alpha
	{ 0, 0, 0, 585, 22, "wolframalpha.com", "/", "http:", "", 1429 },
	--Pandora Audio
	{ 0, 0, 0, 559, 22, "pandora.com%&%audio", "/", "http:", "", 1711 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    gDetector:addHttpPattern(2, 5, 0, 200, 1, 0, 0, 'Arora/0.10.0', 3766, 1)
    gDetector:addHttpPattern(2, 5, 0, 201, 1, 0, 0, 'Browzar', 3777, 1)
    gDetector:addHttpPattern(2, 5, 0, 202, 1, 0, 0, 'CometBird', 3764, 1)
    gDetector:addHttpPattern(2, 5, 0, 203, 1, 0, 0, 'Comodo_Dragon', 1589, 1)
    gDetector:addHttpPattern(2, 5, 0, 204, 1, 0, 0, 'Crazy Browser', 3762, 1)
    gDetector:addHttpPattern(2, 5, 0, 205, 1, 0, 0, 'GreenBrowser', 3763, 1)
    gDetector:addHttpPattern(2, 5, 0, 206, 1, 0, 0, 'PaleMoon', 1592, 1)
    gDetector:addHttpPattern(2, 5, 0, 207, 1, 0, 0, 'Wyzo', 1593, 1)
    gDetector:addHttpPattern(2, 5, 0, 293, 1, 0, 0, 'LiveUpdate', 1428, 1)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end
    return gDetector
end

function DetectorClean()
end
