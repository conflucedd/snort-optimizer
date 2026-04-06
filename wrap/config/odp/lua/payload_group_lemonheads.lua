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
detection_name: Payload Group "Lemonheads"
version: 36
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'NY Daily News' => 'News portal.',
          'Swagbucks' => 'Online rewards program.',
          'Avaya' => 'Network and Communication solution provider.',
          'Walgreens' => 'Online Pharmacy in United States.',
          'Ancestry.com' => 'Online family history resource.',
          'Sohu.com' => 'Chinese search engine with other services like games, advertising, etc.',
          'AllRecipes' => 'Recipes and cooking guide.',
          'Trulia' => 'Online portal for Real Estate.',
          'LiveStrong.com' => 'Health and fitness information.',
          'Kayak' => 'Online Flight and Hotel reservation/deals website.',
          'Reuters' => 'News portal.',
          'Zillow' => 'Online portal for Real Estate.',
          'Square Inc.' => 'Electronic payment service through mobile phones.',
          'Facebook' => 'Facebook is a social networking service.',
          'Fab.com' => 'E-commerce for all articles.',
          'Slickdeals' => 'An online coupons and deals website.',
          'Patch.com' => 'Local news website.',
          'TMZ' => 'Entertainment news.',
          'IMRWorldWide' => 'Market research and Network analytics to display advertisement.',
          'Chartbeat' => 'Realtime Website data for Collection.',
          'Coupons.com' => 'An online coupons and deals website.',
          'Infusionsoft' => 'Software company providing solutions for sales and marketing.',
          'RetailMeNot' => 'Online coupon and deals.',
          'LivingSocial' => 'Deals website.',
          'POLITICO.com' => 'News portal.',
          'California.gov' => 'California government official website.',
          'People.com' => 'Web portal for the Weekly magazine People.',
          'Shutterfly' => 'Share, prints and personalize the cards, album, mugs and other Home decor items with your photos.',
          'AccuWeather' => 'Weather forecasting website.',
          'Sports Illustrated' => 'Web portal for sports news and updates.',
          'T Mobile' => 'Telecommunication and phone service provider.',
          'MapQuest' => 'Map and Driving service by AOL.',
          'Yellow Pages' => 'Online directory and Mapping services.',
          'Wikia' => 'Web portal to contribute and share the knowledge.',
          'Pandora TV' => 'Pandora streaming TV service.',
          'Mail.Ru' => 'Runet\'s free e-mail service.',
          'Examiner.com' => 'News portal.',
          'Bleacher Report' => 'Web Portal for Sports news update.',
          'Disqus' => 'Company which provides discussion forum features.',
          'Food Network' => 'Official website for the TV network about food and cooking.',
          'Apple sites' => 'Apple corporate websites.',
          'NPR' => 'National Public Radio - Associates US national radio station to provide news and other programs.',
          'CBS Sports' => 'Sports news website.',
          'BuzzFeed' => 'News portal.',
          'Fiverr' => 'E-Commerce site generally for $5.',
          'CPX Interactive' => 'Web advertisement services.',
          'Backpage.com' => 'Free classified ads.',
          'OkCupid' => 'Online Dating website.',
          'Sprint' => 'Voice, data and internet service provider.',
          'Neteller' => 'Website for handling online payments and money transactions.',
          'ShopAtHome' => 'An online coupons and deals website.',
          'VeriSign' => 'SSL Certificates provider.',
          'RealClearPolitics' => 'Political news, opinions and polls website.',
          'Business Insider' => 'Online news web portal.',
          'Southwest Airlines' => 'Airlines service in United States.',
          'Stack Overflow' => 'Question and Answering site for programmers.',
          'AddThis' => 'Social bookmarking service.',
          'Salesforce.com Live Agent' => 'Salesforce.com\'s live chat support service.',
          'Snort.org' => 'An open source for Network intrusion prevention system.',
          'Alisoft' => 'IT company for wesites design and development.',
          'Ameba' => 'Japanese blogging and social networking website.',
          'StatCounter' => 'Web traffic analyser.',
          'Intuit' => 'Software company for financial and tax related services.',
          'WorldstarHipHop' => 'Entertainment, hip hop, music videos and blogs.',
          'HostGator' => 'Web hosting portal.',
          'Cox' => 'Telecommunication and wireless service provider.',
          'Legacy.com' => 'Online Obituaries.',
          'Verizon' => 'Internet, TV and Phone service provider.',
          'ClickBank' => 'Online marketplace for Digital products.',
          'WhitePages Inc' => 'Business and People\'s Contact directory in United States.',
          'EarthLink' => 'IT Solution provider for network and communications.',
          'The Blaze' => 'News and Opinion website.',
          'Commission Junction' => 'Web advertisement services.',
          'Goodreads' => 'Book review and cataloging.',
          '1&1 Internet' => 'Internet and Domain name service provider.',
          'Asia Times Online' => 'Web Portal for news update.',
          'Realtor.com' => 'Web portal Real Estate.',
          'ToysRUs' => 'Official website for ToyRUs, which deals with toys.',
          'U.S.Bank' => 'Online banking web portal for U.S Bank.',
          'CNBC' => 'Official website for the CNBC channel which is basically meant for Business and Financial market related news.',
          'InsightExpress' => 'Analyser for online and Mobile advertisements.',
          'NIH' => 'National Institute of Health and Human services.',
          'CareerBuilder.com' => 'Online job search portal.',
          'Monster.com' => 'Online job search portal.',
          'WebMD' => 'Health information service.',
          'Disney' => 'Official Disney website.',
          'HootSuite' => 'Social Network management.',
          'Mashable' => 'News  blog website for social network and new technology.',
          'Inbox.com' => 'Free web-based email service provider.',
          'MGID' => 'Service provider for advertising and marketing.',
          'Manta' => 'Provides US company profiles and information.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_lemonheads",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Apple sites
	{ 0, 0, 0, 1105, 15, "thinkdifferent.us", "/", "http:", "", 1185 },
	--Pandora TV
	{ 0, 0, 0, 839, 5, "pandora.tv", "/", "http:", "", 1327 },
	--Sports Illustrated
	{ 0, 0, 0, 710, 33, "cdn.turner.com", "/si/", "http:", "", 1456 },
	--CPX Interactive
	{ 0, 0, 0, 711, 33, "cpxinteractive.com", "/", "http:", "", 1457 },
	--VeriSign
	{ 0, 0, 0, 712, 33, "verisign.com", "/", "http:", "", 1458 },
	--CBS Sports
	{ 0, 0, 0, 713, 33, "cbssports.com", "/", "http:", "", 1459 },
	--Chartbeat
	{ 0, 0, 0, 714, 33, "chartbeat.com", "/", "http:", "", 1460 },
	--InsightExpress
	{ 0, 0, 0, 715, 33, "insightexpress.com", "/", "http:", "", 1461 },
	--Zillow
	{ 0, 0, 0, 720, 22, "zillow.com", "/", "http:", "", 1480 },
	--Monster.com
	{ 0, 0, 0, 721, 22, "monster.com", "/", "http:", "", 1481 },
	--MapQuest
	{ 0, 0, 0, 722, 22, "mapquest.com", "/", "http:", "", 1482 },
	--Swagbucks
	{ 0, 0, 0, 723, 22, "swagbucks.com", "/", "http:", "", 1483 },
	--Verizon
	{ 0, 0, 0, 724, 22, "verizon.com", "/", "http:", "", 1484 },
	--Wikia
	{ 0, 0, 0, 725, 22, "wikia.com", "/", "http:", "", 1485 },
	--TMZ
	{ 0, 0, 0, 726, 22, "tmz.com", "/", "http:", "", 1486 },
	--ShopAtHome
	{ 0, 0, 0, 727, 22, "shopathome.com", "/", "http:", "", 1487 },
	--Asia Times Online
	{ 0, 0, 0, 728, 33, "atimes.com", "/", "http:", "", 1488 },
	--HootSuite
	{ 0, 0, 0, 729, 22, "hootsuite.com", "/", "http:", "", 1489 },
	--Coupons.com
	{ 0, 0, 0, 730, 15, "coupons.com", "/", "http:", "", 1490 },
	--CareerBuilder.com
	{ 0, 0, 0, 731, 22, "careerbuilder.com", "/", "http:", "", 1491 },
	--Commission Junction
	{ 0, 0, 0, 732, 22, "cj.com", "/", "http:", "", 1492 },
	--Fiverr
	{ 0, 0, 0, 733, 22, "fiverr.com", "/", "http:", "", 1493 },
	--Backpage.com
	{ 0, 0, 0, 734, 22, "backpage.com", "/", "http:", "", 1494 },
	--LivingSocial
	{ 0, 0, 0, 735, 22, "livingsocial.com", "/", "http:", "", 1495 },
	--AllRecipes
	{ 0, 0, 0, 736, 22, "allrecipes.com", "/", "http:", "", 1496 },
	--Yellow Pages
	{ 0, 0, 0, 737, 22, "yellowpages.com", "/", "http:", "", 1497 },
	--Bleacher Report
	{ 0, 0, 0, 738, 22, "bleacherreport.com", "/", "http:", "", 1498 },
	--Stack Overflow
	{ 0, 0, 0, 739, 22, "stackoverflow.com", "/", "http:", "", 1499 },
	--U.S.Bank
	{ 0, 0, 0, 740, 22, "usbank.com", "/", "http:", "", 1500 },
	--Ancestry.com
	{ 0, 0, 0, 741, 22, "ancestry.com", "/", "http:", "", 1501 },
	--WebMD
	{ 0, 0, 0, 742, 22, "webmd.com", "/", "http:", "", 1502 },
	--Trulia
	{ 0, 0, 0, 743, 22, "trulia.com", "/", "http:", "", 1503 },
	--Slickdeals
	{ 0, 0, 0, 744, 22, "slickdeals.net", "/", "http:", "", 1504 },
	--Business Insider
	{ 0, 0, 0, 745, 22, "businessinsider.com", "/", "http:", "", 1505 },
	--People.com
	{ 0, 0, 0, 746, 22, "people.com", "/", "http:", "", 1506 },
	--Reuters
	{ 0, 0, 0, 747, 22, "reuters.com", "/", "http:", "", 1507 },
	--BuzzFeed
	{ 0, 0, 0, 748, 22, "buzzfeed.com", "/", "http:", "", 1508 },
	--California.gov
	{ 0, 0, 0, 749, 22, "ca.gov", "/", "http:", "", 1509 },
	--Southwest Airlines
	{ 0, 0, 0, 750, 22, "southwest.com", "/", "http:", "", 1510 },
	--NIH
	{ 0, 0, 0, 751, 22, "nih.gov", "/", "http:", "", 1511 },
	--WhitePages Inc
	{ 0, 0, 0, 752, 22, "whitepages.com", "/", "http:", "", 1512 },
	--MGID
	{ 0, 0, 0, 753, 22, "mgid.com", "/", "http:", "", 1513 },
	--EarthLink
	{ 0, 0, 0, 754, 22, "earthlink.net", "/", "http:", "", 1514 },
	--Disney
	{ 0, 0, 0, 755, 22, "disney.com", "/", "http:", "", 1515 },
	--POLITICO.com
	{ 0, 0, 0, 756, 22, "politico.com", "/", "http:", "", 1516 },
	--NY Daily News
	{ 0, 0, 0, 757, 22, "nydailynews.com", "/", "http:", "", 1517 },
	--Examiner.com
	{ 0, 0, 0, 758, 22, "examiner.com", "/", "http:", "", 1518 },
	--RetailMeNot
	{ 0, 0, 0, 759, 22, "retailmenot.com", "/", "http:", "", 1519 },
	--AddThis
	{ 0, 0, 0, 760, 22, "addthis.com", "/", "http:", "", 1520 },
	--StatCounter
	{ 0, 0, 0, 761, 22, "statcounter.com", "/", "http:", "", 1521 },
	--OkCupid
	{ 0, 0, 0, 762, 22, "okcupid.com", "/", "http:", "", 1522 },
	--Patch.com
	{ 0, 0, 0, 763, 22, "patch.com", "/", "http:", "", 1523 },
	--Legacy.com
	{ 0, 0, 0, 764, 22, "legacy.com", "/", "http:", "", 1524 },
	--Realtor.com
	{ 0, 0, 0, 765, 22, "realtor.com", "/", "http:", "", 1525 },
	--Intuit
	{ 0, 0, 0, 766, 22, "intuit.com", "/", "http:", "", 1526 },
	--The Blaze
	{ 0, 0, 0, 767, 22, "theblaze.com", "/", "http:", "", 1527 },
	--HostGator
	{ 0, 0, 0, 768, 22, "hostgator.com", "/", "http:", "", 1528 },
	--Food Network
	{ 0, 0, 0, 769, 22, "foodnetwork.com", "/", "http:", "", 1529 },
	--ClickBank
	{ 0, 0, 0, 770, 22, "clickbank.com", "/", "http:", "", 1530 },
	--Cox
	{ 0, 0, 0, 771, 22, "cox.com", "/", "http:", "", 1531 },
	--Mashable
	{ 0, 0, 0, 772, 22, "mashable.com", "/", "http:", "", 1532 },
	--AccuWeather
	{ 0, 0, 0, 773, 22, "accuweather.com", "/", "http:", "", 1533 },
	--Sprint
	{ 0, 0, 0, 774, 22, "sprint.com", "/", "http:", "", 1534 },
	--Goodreads
	{ 0, 0, 0, 775, 22, "goodreads.com", "/", "http:", "", 1535 },
	--LiveStrong.com
	{ 0, 0, 0, 776, 22, "livestrong.com", "/", "http:", "", 1536 },
	--RealClearPolitics
	{ 0, 0, 0, 777, 22, "realclearpolitics.com", "/", "http:", "", 1537 },
	--Manta
	{ 0, 0, 0, 778, 22, "manta.com", "/", "http:", "", 1538 },
	--CNBC
	{ 0, 0, 0, 780, 22, "cnbc.com", "/", "http:", "", 1540 },
	--Inbox.com
	{ 0, 0, 0, 782, 22, "inbox.com", "/", "http:", "", 1542 },
	--Shutterfly
	{ 0, 0, 0, 783, 22, "shutterfly.com", "/", "http:", "", 1543 },
	--Neteller
	{ 0, 0, 0, 784, 22, "neteller.com", "/", "http:", "", 1544 },
	--T Mobile
	{ 0, 0, 0, 785, 22, "t-mobile.com", "/", "http:", "", 1545 },
	--Walgreens
	{ 0, 0, 0, 786, 22, "walgreens.com", "/", "http:", "", 1546 },
	--WorldstarHipHop
	{ 0, 0, 0, 787, 22, "worldstarhiphop.com", "/", "http:", "", 1547 },
	--NPR
	{ 0, 0, 0, 788, 22, "npr.org", "/", "http:", "", 1548 },
	--Kayak
	{ 0, 0, 0, 789, 22, "kayak.com", "/", "http:", "", 1549 },
	--ToysRUs
	{ 0, 0, 0, 790, 22, "toysrus.com", "/", "http:", "", 1550 },
	--Mail.Ru
	{ 0, 0, 0, 791, 22, "mail.ru", "/", "http:", "", 1551 },
	--Sohu.com
	{ 0, 0, 0, 792, 22, "sohu.com", "/", "http:", "", 1552 },
	--1&1 Internet
	{ 0, 0, 0, 793, 22, "1and1.com", "/", "http:", "", 1553 },
	--Ameba
	{ 0, 0, 0, 794, 22, "ameba.jp", "/", "http:", "", 1554 },
	--Avaya
	{ 0, 0, 0, 795, 22, "avaya.com", "/", "http:", "", 1555 },
	--Snort.org
	{ 0, 0, 0, 797, 22, "snort.org", "/", "http:", "", 1557 },
	--Disqus
	{ 0, 0, 0, 798, 22, "disqus.com", "/", "http:", "", 1558 },
	--Infusionsoft
	{ 0, 0, 0, 799, 22, "infusionsoft.com", "/", "http:", "", 1559 },
	--IMRWorldWide
	{ 0, 0, 0, 800, 22, "imrworldwide.com", "/", "http:", "", 1560 },
	--Alisoft
	{ 0, 0, 0, 801, 22, "alisoft.net", "/", "http:", "", 1561 },
	--Salesforce.com Live Agent
	{ 0, 0, 0, 802, 22, "salesforce.com", "/products/instaservice_form.html", "http:", "", 1562 },
	--Fab.com
	{ 0, 0, 0, 806, 22, "fab.com", "/", "http:", "", 1567 },
	--Square Inc.
	{ 0, 0, 0, 807, 22, "squareup.com", "/", "http:", "", 1568 },
	--Facebook
	{ 0, 0, 0, 17, 22, "facebook.net", "/", "http:", "", 629 },
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
