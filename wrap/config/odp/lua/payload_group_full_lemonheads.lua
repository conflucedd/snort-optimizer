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
detection_name: Payload Group Full "Lemonheads"
version: 37
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'AddThis' => 'Social bookmarking service.',
          'Southwest Airlines' => 'Airlines service in United States.',
          'Coupons.com' => 'An online coupons and deals website.',
          'Bleacher Report' => 'Web Portal for Sports news update.',
          'Verizon' => 'Internet, TV and Phone service provider.',
          'InsightExpress' => 'Analyser for online and Mobile advertisements.',
          'T Mobile' => 'Telecommunication and phone service provider.',
          'AccuWeather' => 'Weather forecasting website.',
          'Facebook' => 'Facebook is a social networking service.',
          'Manta' => 'Provides US company profiles and information.',
          'Mashable' => 'News  blog website for social network and new technology.',
          'EarthLink' => 'IT Solution provider for network and communications.',
          'ToysRUs' => 'Official website for ToyRUs, which deals with toys.',
          'Asia Times Online' => 'Web Portal for news update.',
          'RetailMeNot' => 'Online coupon and deals.',
          'Salesforce.com Live Agent' => 'Salesforce.com\'s live chat support service.',
          'Cox' => 'Telecommunication and wireless service provider.',
          'The Blaze' => 'News and Opinion website.',
          'MapQuest' => 'Map and Driving service by AOL.',
          'Infusionsoft' => 'Software company providing solutions for sales and marketing.',
          'Chartbeat' => 'Realtime Website data for Collection.',
          'Reuters' => 'News portal.',
          'LiveStrong.com' => 'Health and fitness information.',
          'BuzzFeed' => 'News portal.',
          'Square Inc.' => 'Electronic payment service through mobile phones.',
          'OkCupid' => 'Online Dating website.',
          'Fiverr' => 'E-Commerce site generally for $5.',
          'Yellow Pages' => 'Online directory and Mapping services.',
          'Slickdeals' => 'An online coupons and deals website.',
          'LivingSocial' => 'Deals website.',
          'Zillow' => 'Online portal for Real Estate.',
          'Wikia' => 'Web portal to contribute and share the knowledge.',
          'Sports Illustrated' => 'Web portal for sports news and updates.',
          'Trulia' => 'Online portal for Real Estate.',
          'Stack Overflow' => 'Question and Answering site for programmers.',
          'WhitePages Inc' => 'Business and People\'s Contact directory in United States.',
          'Apple sites' => 'Apple corporate websites.',
          'Intuit' => 'Software company for financial and tax related services.',
          'ShopAtHome' => 'An online coupons and deals website.',
          'CareerBuilder.com' => 'Online job search portal.',
          'Disney' => 'Official Disney website.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_lemonheads",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Apple sites
	{ 0, 0, 0, 1105, 15, "apple.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "mac.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.ru", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.co.uk", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "acot2.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "airport.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "airtunes.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "aple.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appl-e.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appl.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appl3e.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applde.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple-darwin.net", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple-imac.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple-ipod.ca", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.be", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.ch", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.co", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.co.kr", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.com.au", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.com.pa", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.com.pr", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.com.uy", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.it", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.net.gr", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "apple.tv", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applebrazil.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applecomputer.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applecomputerinc.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appleimac.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appleiphone.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appleipod.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applemagicmouse.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applemagictrackpad.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applemalaysia.com.my", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appleoslion.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appleosxlion.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applereach.net", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applestore.bg", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "applethunderboltdisplay.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appletrackpad.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "appstore.fr", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "carbon.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "calendarserver.org", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "cups.org", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "desktopmovie.net", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "dvdstudiopro.info", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "dvdstudiopro.net", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "finalcutpro.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "fonts.apple.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "garageband.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "genius-bar.eu", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ibook.co", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ichat.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "imac-apple.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "imac.co", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "imac.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "imacapple.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "imacapplecomputer.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "imacstore.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipad3.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphone.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphone.org", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphone4.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphone4.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphone4s.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphoneacessorios.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphoneclaro.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iphoto.se", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipod.ca", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipod.cm", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipod.co", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipod.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipod.ua", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipodnano.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ipods.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "iwork.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "lojaiphone.com.br", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "mac.eu", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macbook.co", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macbookair.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macbookpro.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macintosh.cl", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macintosh.co", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macmini.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macoslion.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macosxleo.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macosxleon.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macosxlion.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "macosxserver.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "magictrackpad.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "metapushpin.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "myapple.net", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "nothingreal.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "playquicktime.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "powerbook.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "prismo.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "publishing-research.org", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "publishingsurvey.org", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "quicktime.cc", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "quicktime.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "quicktime.eu", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "rip-mix-burn.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "ripmixburn.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "thinkdifferent.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "whiteiphone.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "whyapple.co.za", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "xserve.com", "/", "http:", "", 1185 },
	{ 0, 0, 0, 1105, 15, "zpple.com", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "instore.apple.com", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "mac-mini.com", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "quicktime-player.com", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "quicktime.net", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "quicktime.tv", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "quicktime5.com", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "quicktimetv.com", "/", "http:", "", 1185 },
	--{ 0, 0, 0, 1105, 15, "webobjects.net", "/", "http:", "", 1185 },
	--Sports Illustrated
	{ 0, 0, 0, 710, 33, "si.com", "/", "http:", "", 1456 },
	--{ 0, 0, 0, 710, 33, "sportsillustrated.fyre.co", "/", "http:", "", 1456 },
	--Chartbeat
	{ 0, 0, 0, 714, 33, "chartbeat.net", "/", "http:", "", 1460 },
	--InsightExpress
	{ 0, 0, 0, 715, 33, "ad.insightexpressai.com", "/", "http:", "", 1461 },
	--Zillow
	{ 0, 0, 0, 720, 22, "zillowstatic.com", "/", "http:", "", 1480 },
	--Monster.com
	--{ 0, 0, 0, 721, 22, "monster.prospero.com", "/", "http:", "", 1481 },
	--MapQuest
	{ 0, 0, 0, 722, 22, "mqcdn.com", "/", "http:", "", 1482 },
	--Swagbucks
	--{ 0, 0, 0, 723, 22, "sbx-cdn.com", "/", "http:", "", 1483 },
	--Verizon
	{ 0, 0, 0, 724, 22, "verizon.net", "/", "http:", "", 1484 },
	--Wikia
	{ 0, 0, 0, 725, 22, "wikia.nocookie.net", "/", "http:", "", 1485 },
	{ 0, 0, 0, 725, 22, "a.wikia-beacon.com", "/", "http:", "", 1485 },
	--ShopAtHome
	{ 0, 0, 0, 727, 22, "sahcdn.com", "/", "http:", "", 1487 },
	--Asia Times Online
	{ 0, 0, 0, 728, 33, "asiatimes.com", "/", "http:", "", 1488 },
	--Coupons.com
	{ 0, 0, 0, 730, 15, "cpnscdn.com", "/", "http:", "", 1490 },
	{ 0, 0, 0, 730, 15, "couponsinc.com", "/", "http:", "", 1490 },
	--CareerBuilder.com
	{ 0, 0, 0, 731, 22, "icbdr.com", "/", "http:", "", 1491 },
	--Fiverr
	{ 0, 0, 0, 733, 22, "fiverrcdn.com", "/", "http:", "", 1493 },
	--LivingSocial
	{ 0, 0, 0, 735, 22, "lscdn.net", "/", "http:", "", 1495 },
	--Yellow Pages
	{ 0, 0, 0, 737, 22, "yp.com", "/", "http:", "", 1497 },
	{ 0, 0, 0, 737, 22, "ypcdn.com", "/", "http:", "", 1497 },
	{ 0, 0, 0, 737, 22, "yellowpages.in", "/", "http:", "", 1497 },
	--Bleacher Report
	{ 0, 0, 0, 738, 22, "bleacherreport.net", "/", "http:", "", 1498 },
	--Stack Overflow
	{ 0, 0, 0, 739, 22, "cdn.sstatic.net", "/stackoverflow", "http:", "", 1499 },
	--Trulia
	{ 0, 0, 0, 743, 22, "trulia-cdn.com", "/", "http:", "", 1503 },
	--Slickdeals
	{ 0, 0, 0, 744, 22, "slickdealz.net", "/", "http:", "", 1504 },
	--People.com
	--{ 0, 0, 0, 746, 22, "timeinc.net", "/people", "http:", "", 1506 },
	--{ 0, 0, 0, 746, 22, "peoplestylewatch.com", "/", "http:", "", 1506 },
	--Reuters
	{ 0, 0, 0, 747, 22, "reutersmedia.net", "/", "http:", "", 1507 },
	{ 0, 0, 0, 747, 22, "reutersmedia.com", "/", "http:", "", 1507 },
	--BuzzFeed
	{ 0, 0, 0, 748, 22, "buzzfed.com", "/", "http:", "", 1508 },
	--Southwest Airlines
	{ 0, 0, 0, 750, 22, "southwestairlines.tt.omtrdc.net", "/", "http:", "", 1510 },
	--WhitePages Inc
	{ 0, 0, 0, 752, 22, "whitepagesinc.com", "/", "http:", "", 1512 },
	--{ 0, 0, 0, 752, 22, "cdnwp.com", "/", "http:", "", 1512 },
	--EarthLink
	{ 0, 0, 0, 754, 22, "earthlinkbusiness.com", "/", "http:", "", 1514 },
	--Disney
	{ 0, 0, 0, 755, 22, "disney.go.com", "/", "http:", "", 1515 },
	{ 0, 0, 0, 755, 22, "disneyinternational.com", "/", "http:", "", 1515 },
	{ 0, 0, 0, 755, 22, "disney.co.uk", "/", "http:", "", 1515 },
	--NY Daily News
	--{ 0, 0, 0, 757, 22, "nydailynews.stat.com", "/", "http:", "", 1517 },
	--RetailMeNot
	{ 0, 0, 0, 759, 22, "rmncdn.com", "/", "http:", "", 1519 },
	--AddThis
	{ 0, 0, 0, 760, 22, "addthiscdn.com", "/", "http:", "", 1520 },
	--OkCupid
	{ 0, 0, 0, 762, 22, "okccdn.com", "/", "http:", "", 1522 },
	{ 0, 0, 0, 762, 22, "okcimg.com", "/", "http:", "", 1522 },
	--Patch.com
	--{ 0, 0, 0, 763, 22, "assets0.patch-assets.com", "/", "http:", "", 1523 },
	--Intuit
	{ 0, 0, 0, 766, 22, "intuitstatic.com", "/", "http:", "", 1526 },
	--The Blaze
	{ 0, 0, 0, 767, 22, "gbtv.com", "/", "http:", "", 1527 },
	--Cox
	{ 0, 0, 0, 771, 22, "cox.net", "/", "http:", "", 1531 },
	{ 0, 0, 0, 771, 22, "coxcablespecial.com", "/", "http:", "", 1531 },
	--Mashable
	{ 0, 0, 0, 772, 22, "mshcdn.com", "/", "http:", "", 1532 },
	--AccuWeather
	{ 0, 0, 0, 773, 22, "accu-weather.com", "/", "http:", "", 1533 },
	--LiveStrong.com
	{ 0, 0, 0, 776, 22, "lsimg.net", "/", "http:", "", 1536 },
	--Manta
	{ 0, 0, 0, 778, 22, "manta-r1.com", "/", "http:", "", 1538 },
	--T Mobile
	{ 0, 0, 0, 785, 22, "tmobile.tt.omtrdc.net", "/", "http:", "", 1545 },
	{ 0, 0, 0, 785, 22, "tmocache.com", "/", "http:", "", 1545 },
	{ 0, 0, 0, 785, 22, "tmobile.com", "/", "http:", "", 1545 },
	{ 0, 0, 0, 785, 22, "tmocce.com", "/", "http:", "", 1545 },
    --[[ Tmobile (VoIP services). is a Thirdparty-only detection, this makes the unit-test happy
        dummy = 471
    --]]
	--ToysRUs
	{ 0, 0, 0, 790, 22, "trus.imageg.net", "/", "http:", "", 1550 },
	--1&1 Internet
	--{ 0, 0, 0, 793, 22, "1und1.ivwbox.de", "/", "http:", "", 1553 },
	--Axifile (Deprecated)
	--{ 0, 0, 0, 796, 22, "axifile.com", "/", "http:", "", 1556 },
	--Infusionsoft
	{ 0, 0, 0, 799, 22, "insft.com", "/", "http:", "", 1559 },
	--Salesforce.com Live Agent
	{ 0, 0, 0, 802, 22, "liveagentforsalesforce.com", "/", "http:", "", 1562 },
	--Square Inc.
	{ 0, 0, 0, 807, 22, "square.com", "/", "http:", "", 1568 },
	--Facebook
	{ 0, 0, 0, 17, 22, "facebook.com", "/", "http:", "", 629 },
	{ 0, 0, 0, 17, 22, "fbcdn.net", "/", "http:", "", 629 },
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
