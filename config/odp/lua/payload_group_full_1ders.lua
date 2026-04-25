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
detection_name: Payload Group Full "1derss"
version: 46
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Apple Update' => 'Apple software updating tool.',
          'SlideShare' => 'A web-based slide show service.',
          'Adenin' => 'A web portal.',
          'MaxPoint Interactive' => 'Advertisement site.',
          'eBay' => 'An online auction and shopping website.',
          'Softonic' => 'Software download site.',
          'Delta Search' => 'A search engine, with a toolbar that is commonly installed by mistake.',
          'Online File Folder' => 'Cloud-based file storage.',
          'TechInline' => 'Website that offers remote desktop control.',
          'Mozilla' => 'Website for many open source software projects, including the Firefox browser.',
          'Netease' => 'Chinese web portal.',
          'LINE' => 'Mobile and Desktop App for Instant Messaging.',
          'Engage BDR' => 'Advertisement site.',
          'TowerData' => 'Formerly RapLeaf, an advertisement site.',
          'QQ' => 'Chinese instant messaging software.',
          'RhythmOne' => 'Advertisement site.',
          'InSkin Media' => 'Advertisement site.',
          'Narratiive' => 'Advertisement site.',
          'IKEA.com' => 'Online storefront for international furniture retailer.',
          'Apple Maps' => 'Apple maps and navigation.',
          'Sourceforge' => 'Site for sharing open source software projects.',
          'eBay Bid' => 'Bidding in an eBay Auction.',
          'Marca' => 'Primarily Spanish video streaming site.',
          'MediaV' => 'Advertisement site.',
          'Neustar Information Services' => 'Advertisement site.',
          'Mercado Livre' => 'Brazil online auction and shopping website.',
          'Quote.com' => 'Financial research and trading website.',
          'eBay Search' => 'Browsing eBay listings.',
          'Six Apart' => 'Advertisement site.',
          'Motley Fool' => 'Financial and Investment community.',
          'SLI Systems' => 'Advertisement site.',
          'Improve Digital' => 'European sell side online ad service.',
          'EQ Ads' => 'Advertisement site.',
          'Naverisk' => 'Cloud-based remote monitoring and management software.',
          'Hotspot Shield' => 'Anonymizer and tunnel that encrypts communications.',
          'eBay Watch' => 'Watching an item on eBay.',
          'Proclivity' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_1ders",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Hotspot Shield
	{ 0, 0, 0, 1502, 22, "hsselite.com", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "hsselite.zendesk.com", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "anchorfree.us", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "anchorfree.com", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "anchorfree.net", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "hotspotshield.s3.amazonaws.com", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "a433.com", "/", "http:", "", 1140 },
	{ 0, 0, 0, 1502, 22, "event.shelljacket.us", "/", "http:", "", 1140 },
	--SlideShare
	{ 0, 0, 0, 1621, 9, "slideshare.net", "/", "http:", "", 1176 },
	--Sourceforge
	{ 0, 0, 0, 1628, 22, "sf.net", "/", "http:", "", 1177 },
	--Netease
	{ 0, 0, 0, 1570, 22, "163.com", "/", "http:", "", 1222 },
	{ 0, 0, 0, 1570, 22, "127.net", "/", "http:", "", 1222 },
	--Online File Folder
	{ 0, 0, 0, 1579, 9, "login.secureserver.net", "/", "http:", "", 1223 },
	--Mozilla
	{ 0, 0, 0, 1565, 8, "mozilla.org", "/", "http:", "", 1261 },
	--eBay
	{ 0, 0, 0, 1551, 45, "ebay.co.uk", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.ca", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.com.au", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.ie", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.de", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.in", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.fr", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.es", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.it", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.at", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.be", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "benl.ebay.be", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "befr.ebay.be", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.nl", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.ch", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.pl", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.com.sg", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.com.cn", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.cn", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.com.tw", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.com.hk", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.co.jp", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.co.kr", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.ph", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.com.my", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.vn", "/", "http:", "", 132 },
	{ 0, 0, 0, 1551, 45, "ebay.co.th", "/", "http:", "", 132 },
	--{ 0, 0, 0, 1551, 45, "id.ebay.com", "/", "http:", "", 132 },
	--eBay Bid
	{ 0, 0, 0, 32, 45, "offer.ebay.co.uk", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.ca", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.com.au", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.ie", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.de", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.in", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.fr", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.es", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.it", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.at", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.be", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.benl.ebay.be", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.befr.ebay.be", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.nl", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.ch", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.pl", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.com.sg", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.com.cn", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.cn", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.com.tw", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.com.hk", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.co.jp", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.co.kr", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.ph", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.com.my", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.vn", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.ebay.co.th", "/", "http:", "", 133 },
	{ 0, 0, 0, 32, 45, "offer.id.ebay.com", "/", "http:", "", 133 },
	--eBay Search
	{ 0, 0, 0, 33, 45, "ebay.co.uk", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.ca", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.com.au", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.ie", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.de", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.in", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.fr", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.es", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.it", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.at", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.be", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "benl.ebay.be", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "befr.ebay.be", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.nl", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.ch", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.pl", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.com.sg", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.com.cn", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.cn", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.com.tw", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.com.hk", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.co.jp", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.co.kr", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.ph", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.com.my", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.vn", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "ebay.co.th", "/sch", "http:", "", 134 },
	{ 0, 0, 0, 33, 45, "id.ebay.com", "/sch", "http:", "", 134 },
	--eBay Watch
	{ 0, 0, 0, 34, 45,  "ebay.co.uk", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.ca", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.com.au", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.ie", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.de", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.in", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.fr", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.es", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.it", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.at", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.be", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "benl.ebay.be", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "befr.ebay.be", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.nl", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.ch", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.pl", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.com.sg", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.com.cn", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.cn", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.com.tw", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.com.hk", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.co.jp", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.co.kr", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.ph", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.com.my", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.vn", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "ebay.co.th", "/myb/WatchList", "http:", "", 135 },
	{ 0, 0, 0, 34, 45,  "id.ebay.com", "/myb/WatchList", "http:", "", 135 },
	--LINE
	{ 0, 210, 16, 1528, 49, "line-apps.com", "/", "http:", "", 1667 },
	{ 0, 210, 16, 1528, 49, "line-scdn.net", "/", "http:", "", 1667 },
	{ 0, 210, 16, 1528, 49, "line.naver.jp", "/", "http:", "", 1667 },
	--IKEA.com
	{ 0, 0, 0, 1510, 22, "ikea.us", "/", "http:", "", 2349 },
	{ 0, 0, 0, 1510, 22, "ikea-usa.com", "/", "http:", "", 2349 },
	{ 0, 0, 0, 1510, 22, "ikea.is", "/", "http:", "", 2349 },
	--TechInline
	{ 0, 0, 0, 1639, 8, "fixme.it", "/", "http:", "", 2351 },
	--Quote.com
	{ 0, 0, 0, 1603, 39, "thestockmarketwatch.com", "/", "http:", "", 2353 },
	--Adenin
	{ 0, 0, 0, 1543, 43, "dynamicintranet.com", "/", "http:", "", 2360 },
	--MUZU TV (Deprecated)
	--{ 0, 0, 0, 1566, 13, "muzu.tv", "/", "http:", "", 2375 },
	--Apple Maps
	{ 0, 468, 27, 1586, 22, "ls.apple.com", "/", "http:", "", 2381 },
	--Naverisk
	{ 0, 0, 0, 1569, 8, "naveriskusa.com", "/", "http:", "", 2390 },
	--Improve Digital
	{ 0, 0, 0, 1512, 22, "360yield.com", "/", "http:", "", 2451 },
	--Marca
	{ 0, 0, 0, 1535, 1, "marca.es", "/", "http:", "", 2486 },
	--SLI Systems
	{ 0, 0, 0, 1620, 22, "sli-systems.co.uk", "/", "http:", "", 2494 },
	{ 0, 0, 0, 1620, 22, "sli-systems.com.au", "/", "http:", "", 2494 },
	{ 0, 0, 0, 1620, 22, "sli-systems.com.br", "/", "http:", "", 2494 },
	{ 0, 0, 0, 1620, 22, "sli-systems.co.jp", "/", "http:", "", 2494 },
	{ 0, 0, 0, 1620, 22, "tools.sli-systems.com", "/", "http:", "", 2494 },
	--MediaV
	{ 0, 0, 0, 1553, 22, "mediav.cn", "/", "http:", "", 2501 },
	{ 0, 0, 0, 1553, 22, "fenxi.com", "/", "http:", "", 2501 },
	--Narratiive
	{ 0, 0, 0, 1550, 45, "effectivemeasure.com", "/", "http:", "", 2516 },
	--LiveRail (Deprecated)
	--{ 0, 0, 0, 1531, 22, "liverail.com", "/", "http:", "", 2520 },
	--InSkin Media
	{ 0, 0, 0, 1515, 22, "inskinad.com", "/", "http:", "", 2527 },
	--Ohana (Deprecated)
	--{ 0, 0, 0, 1577, 22, "ohana-media.com", "/", "http:", "", 2531 },
	--{ 0, 0, 0, 1577, 22, "networkohana.com", "/", "http:", "", 2531 },
	--{ 0, 0, 0, 1577, 22, "bsrv.adohana.com", "/", "http:", "", 2531 },
	--Proclivity
	{ 0, 0, 0, 1599, 22, "t.pswec.com", "/", "http:", "", 2533 },
	--Neustar Information Services
	{ 0, 0, 0, 1491, 22, "neustar.biz", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "neustarlife.biz", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "neustarsummit.biz", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "neustarlocaleze.biz", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "neustarlocaleze.com", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "ultradns.com", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "webmetrics.com", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "tcpacompliance.us", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "tcpacompliance.com", "/", "http:", "", 2537 },
	{ 0, 0, 0, 1491, 22, "npac.com", "/", "http:", "", 2537 },
	--EQ Ads
	{ 0, 0, 0, 1546, 22, "eqworks.com", "/", "http:", "", 2539 },
	--TowerData
	{ 0, 0, 0, 1607, 22, "towerdata.com", "/", "http:", "", 2540 },
	--Engage BDR
	{ 0, 0, 0, 1548, 16, "bnmla.com", "/", "http:", "", 2554 },
	{ 0, 0, 0, 1548, 16, "first-impression.com", "/", "http:", "", 2554 },
	--Six Apart
	{ 0, 0, 0, 1618, 22, "sixapart.jp", "/", "http:", "", 2560 },
	{ 0, 0, 0, 1618, 22, "movabletype.com", "/", "http:", "", 2560 },
	--MaxPoint Interactive
	{ 0, 0, 0, 1537, 22, "maxpoint-express.com", "/", "http:", "", 2561 },
	--RhythmOne
	{ 0, 0, 0, 1604, 22, "rhythmone.com", "/", "http:", "", 2564 },
	--Telemetry (Deprecated)
	--{ 0, 0, 0, 1640, 22, "telemetry.com", "/", "http:", "", 2596 },
	--Softonic
	{ 0, 0, 0, 1623, 22, "softonic.fr", "/", "http:", "", 2599 },
	{ 0, 0, 0, 1623, 22, "softonic.de", "/", "http:", "", 2599 },
	{ 0, 0, 0, 1623, 22, "softonic.it", "/", "http:", "", 2599 },
	{ 0, 0, 0, 1623, 22, "softonic.com.br", "/", "http:", "", 2599 },
	{ 0, 0, 0, 1623, 22, "softonic.cn", "/", "http:", "", 2599 },
	{ 0, 0, 0, 1623, 22, "softonic.pl", "/", "http:", "", 2599 },
	{ 0, 0, 0, 1623, 22, "softonic.jp", "/", "http:", "", 2599 },
	--Mercado Livre
	{ 0, 0, 0, 1555, 30, "mercadolibre.com", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolivre.com.br", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.ar", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.co", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.co.cr", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.cl", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.do", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.ec", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.mx", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.pa", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.pe", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolivre.pt", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.uy", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadolibre.com.ve", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadopago.com", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadopago.com.br", "/", "http:", "", 2860 },
	{ 0, 0, 0, 1555, 30, "mercadoshops.com.br", "/", "http:", "", 2860 },
	--Motley Fool
	{ 0, 0, 0, 1563, 39, "fool.ca", "/", "http:", "", 2863 },
	{ 0, 0, 0, 1563, 39, "fool.co.uk", "/", "http:", "", 2863 },
	{ 0, 0, 0, 1563, 39, "fool.com.au", "/", "http:", "", 2863 },
	{ 0, 0, 0, 1563, 39, "fool.sg", "/", "http:", "", 2863 },
	--Meta5 (Deprecated)
	--{ 0, 0, 0, 1556, 30, "meta5.us", "/", "http:", "", 288 },
	--{ 0, 0, 0, 1556, 30, "meta5.com", "/", "http:", "", 288 },
	--Apple Update
	{ 0, 0, 0, 1585, 6, "swcdn.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "phobos.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "swscan.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "swquery.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "skl.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "swdist.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "updates-http.cdn-apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "iosapps.itunes.apple.com", "/", "http:", "", 32 },
	{ 0, 0, 0, 1585, 6, "updates.cdn-apple.com", "/", "http:", "", 32 },
	--Delta Search
	{ 0, 0, 0, 1493, 22, "royal-search.com", "/", "http:", "", 3657 },
	--OpenCandy (Deprecated)
	--{ 0, 0, 0, 1497, 22, "opencandy.com", "/", "http:", "", 3672 },
	--Netfolder.in (Deprecated)
	--{ 0, 0, 0, 1590, 22, "netfolder.in", "/", "http:", "", 3814 },
	--QQ
	{ 0, 0, 0, 1600, 10, "imqq.com", "/", "http:", "", 386 },
	{ 0, 0, 0, 1600, 10, "gtimg.com", "/", "http:", "", 386 },
	{ 0, 0, 0, 1600, 10, "qpic.cn.com", "/", "http:", "", 386 },
	{ 0, 0, 0, 1600, 10, "qpic.cn", "/", "http:", "", 386 },
	{ 0, 0, 0, 1600, 10, "pub.idqqimg.com", "/", "http:", "", 386 },
	{ 0, 0, 0, 1600, 10, "thirdqq.qlogo.cn", "/", "http:", "", 386 },
	{ 0, 0, 0, 1600, 10, "gtimg.cn", "/", "http:", "", 386 },
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
