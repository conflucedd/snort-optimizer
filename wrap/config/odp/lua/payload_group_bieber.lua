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
detection_name: Payload Group "Bieber"
version: 28
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Vanguard' => 'Investment management company.',
          'oo.com.au' => 'Australian and New Zealand online department store.',
          'Netflix' => 'Rental and on-demand internet television and movie streaming website.',
          'American Express' => 'Financial services company.',
          'Redmine' => 'Web based bug tracking and project management tool.',
          'GameStop' => 'Video game retailer.',
          'Neckermann' => 'General goods online retailer.',
          'AutoTrader.com' => 'Used car listings by owner or dealer.',
          'Windows Live SkyDrive' => 'Cloud based file hosting service.',
          'Tickets.com' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'ProFlowers' => 'United States\' flower retailer.',
          'Zales' => 'Jewelry retailer.',
          'TD Ameritrade' => 'Online stock brokerage service.',
          'Office Depot' => 'Office supply retailer.',
          'Travelocity' => 'Online travel agency.',
          'FogBugz' => 'Web-based project management and bug tracking system.',
          'Dick\'s Sporting Goods' => 'Retailer focused on sporting goods.',
          'FTD' => 'Floral retailer.',
          'QVC' => 'General shopping website in association with its related televised QVC broadcasts.',
          'Trac' => 'Web based bug tracking and project management tool.',
          'The Sharper Image' => 'General electronics and gifts retailer.',
          'Gawker' => 'Online blog based around media news and gossip.',
          'Jira' => 'Web based bug tracking and project management tool.',
          'Tiger Direct' => 'Online computer and electronics retailer.',
          'Tchibo' => 'German retailer with weekly changing products.',
          'Salesforce.com' => 'Enterprise cloud computing company.',
          'Edmunds.com' => 'General automotive information website.',
          'Ticketmaster' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'Overstock.com' => 'Online discount retailer.',
          'Victoria\'s Secret' => 'Woman\'s wear, lingerie, and beauty product retailer.',
          'CarMax' => 'New and used car retailer.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'HP Home & Home Office Store' => 'HP\'s online store for computers and related products.',
          'Launchpad' => 'Web based bug tracking and project management tool.',
          'Chase' => 'Consumer and commercial banking company.',
          'Craigslist' => 'Popular online classifieds.',
          'Backblaze' => 'Online backup tool for Windows and Mac users.',
          'Zynga' => 'Social network game developer.',
          'Costco' => 'Warehouse club\'s online retail website.',
          'Kohl\'s' => 'Department store/retailer.',
          'Woot' => 'Online retailer that sells one discount product a day.',
          'Discover' => 'Financial services company.',
          'ShopNBC' => 'General shopping website in association with it\'s related televised shopNBC broadcasts.',
          'Bing' => 'Microsoft\'s internet search engine.',
          'E*TRADE' => 'Financial services company with a focus on online stock brokerage.',
          'Wells Fargo' => 'Global financial services company.',
          'Kmart' => 'Discount department store/retailer.',
          'Walmart' => 'Discount department store.',
          'Deals Direct' => 'Australian discount retailer.',
          'Google Product Search' => 'Google e-commerce site.',
          'The Gap' => 'Clothing and accessories retailer, encompassing Gap, Old Navy, Banana Republic, Piperlime, and Athleta.',
          'Car and Driver' => 'American automotive enthusiast news site.',
          'Zappos' => 'Online shoe and apparel retailer.',
          'Dell' => 'Computer and related technologies retailer.',
          'Capital One' => 'U.S. based bank holding company.',
          'Sears' => 'Department store retailer.',
          'Top Gear' => 'Website for the related British TV series focused on cars.',
          'Jalopnik' => 'Automotive news and information blog.',
          'Basecamp' => 'Web based project management tool.',
          'CDiscount' => 'French online retailer.',
          'T. Rowe Price' => 'Public investment firm.',
          'Lowe\'s' => 'Home improvement and appliance retailer.',
          'CamerasDirect.com.au' => 'Australian camera and photography gear retailer.',
          'Target' => 'Discount retailer.',
          'Kay Jewelers' => 'Retail jeweller.',
          'Home Depot' => 'Retailer for home improvement and construction goods/products.',
          'Fnac' => 'International retail chain focused on cultural and electronic products.',
          'Crutchfield' => 'Electronics retailer.',
          'RitzCamera.com' => 'Photography goods and electronics retailer.',
          'GoToMeeting' => 'Online meeting and desktop sharing service.',
          'Kogan Technologies' => 'Australian retailer of consumer electronic devices.',
          'Schwab' => 'Brokerage and banking company.',
          'Staples' => 'Office supply retailer.',
          'Newegg' => 'Computer hardware and software retailer.',
          'Citi' => 'Financial services company.',
          'Bank of America' => 'Global financial services company.',
          'HSBC' => 'Global banking and financial services company.',
          'Blockbuster' => 'Movie and video game rental/streaming website.',
          'IGN' => 'News/reviews website focused primarily on video games.',
          'Wikipedia' => 'Collaborative, user-written online encyclopedia.',
          'J.C. Penney' => 'Clothing and accessory retailer.',
          'Expedia' => 'Travel reservation website.',
          'Morgan Stanley' => 'Global financial services firm.',
          'GameSpot' => 'Video game previews/reviews/news website.',
          'Kotaku' => 'Video game focused blog.',
          'REI' => 'Outdoor sporting clothing and gear retailer.',
          'Autoblog' => 'Automobile news and information site.',
          'vente-privee.com' => 'Private online shopping club focused on fashion and lifestyle products.',
          'Sam\'s Club' => 'Warehouse club\'s online retail site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_bieber",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--FogBugz
	{ 0, 0, 0, 120, 43, "fogbugz.com", "/", "http:", "", 161 },
	--GoToMeeting
	{ 0, 0, 0, 124, 21, "gotomeeting.co", "/", "http:", "", 187 },
	--Backblaze
	{ 0, 0, 0, 112, 9, "backblaze.com", "/", "http:", "", 47 },
	--Wikipedia
	{ 0, 0, 0, 187, 8, "wikipedia.org", "/", "http:", "", 501 },
	--Zynga
	{ 0, 0, 0, 137, 20, "zynga.com", "/", "http:", "", 533 },
	--American Express
	{ 0, 0, 0, 110, 39, "americanexpress.co", "/", "http:", "", 544 },
	--Autoblog
	{ 0, 0, 0, 197, 35, "autoblog.com", "/", "http:", "", 557 },
	--AutoTrader.com
	{ 0, 0, 0, 194, 36, "autotrader.com", "/", "http:", "", 558 },
	--Bank of America
	{ 0, 0, 0, 113, 39, "bankofamerica.co", "/", "http:", "", 560 },
	--Basecamp
	{ 0, 0, 0, 204, 43, "basecamphq.com", "/", "http:", "", 563 },
	--Blockbuster
	{ 0, 0, 0, 192, 38, "blockbuster.co", "/", "http:", "", 575 },
	--Bing
	{ 0, 0, 0, 114, 22, "bing.com", "/", "http:", "", 58 },
	--CamerasDirect.com.au
	{ 0, 0, 0, 138, 27, "camerasdirect.com.au", "/", "http:", "", 581 },
	--Capital One
	{ 0, 0, 0, 115, 39, "capitalone.co", "/", "http:", "", 582 },
	--Car and Driver
	{ 0, 0, 0, 195, 35, "caranddriver.com", "/", "http:", "", 583 },
	--CarMax
	{ 0, 0, 0, 139, 36, "carmax.com", "/", "http:", "", 584 },
	--CDiscount
	{ 0, 0, 0, 140, 45, "cdiscount.com", "/", "http:", "", 585 },
	--Chase
	{ 0, 0, 0, 191, 39, "chase.com", "/", "http:", "", 587 },
	--Citi
	{ 0, 0, 0, 116, 39, "citi.com", "/", "http:", "", 590 },
	--Costco
	{ 0, 0, 0, 141, 30, "costco.co", "/", "http:", "", 593 },
	--Craigslist
	{ 0, 0, 0, 206, 15, "craigslist.org", "/", "http:", "", 594 },
	--Crutchfield
	{ 0, 0, 0, 142, 27, "crutchfield.com", "/", "http:", "", 595 },
	--Deals Direct
	{ 0, 0, 0, 143, 30, "dealsdirect.com.au", "/", "http:", "", 604 },
	--Dell
	{ 0, 0, 0, 144, 27, "dell.com", "/", "http:", "", 606 },
	--Dick's Sporting Goods
	{ 0, 0, 0, 193, 29, "dickssportinggoods.com", "/", "http:", "", 611 },
	--Discover
	{ 0, 0, 0, 117, 42, "discovercard.com", "/", "http:", "", 615 },
	--Drugstore.com
	--{ 0, 0, 0, 145, 45, "drugstore.com", "/", "http:", "", 620 },
	--E*TRADE
	{ 0, 0, 0, 118, 41, "etrade.com", "/", "http:", "", 621 },
	--Edmunds.com
	{ 0, 0, 0, 146, 36, "edmunds.com", "/", "http:", "", 622 },
	--Expedia
	{ 0, 0, 0, 147, 37, "expedia.co", "/", "http:", "", 628 },
	--Fidelity
	{ 0, 0, 0, 119, 39, "fidelity.com", "/", "http:", "", 636 },
	--Fnac
	{ 0, 0, 0, 148, 45, "fnac.com", "/", "http:", "", 640 },
	--FTD
	{ 0, 0, 0, 150, 25, "ftd.com", "/", "http:", "", 644 },
	--GameSpot
	{ 0, 0, 0, 121, 34, "gamespot.co", "/", "http:", "", 648 },
	--GameStop
	{ 0, 0, 0, 122, 28, "gamestop.com", "/", "http:", "", 650 },
	--Gawker
	{ 0, 0, 0, 123, 33, "gawker.com", "/", "http:", "", 652 },
	--Google Product Search
	{ 0, 0, 0, 151, 22, "shopping.google.co", "/", "http:", "", 664 },
	--Home Depot
	{ 0, 0, 0, 152, 44, "homedepot.com", "/", "http:", "", 670 },
	--HSBC
	{ 0, 0, 0, 125, 39, "hsbc.co", "/", "http:", "", 675 },
	--IGN
	{ 0, 0, 0, 126, 34, "ign.com", "/", "http:", "", 680 },
	--J.C. Penney
	{ 0, 0, 0, 154, 45, "jcpenney.com", "/", "http:", "", 690 },
	--Jalopnik
	{ 0, 0, 0, 196, 35, "jalopnik.com", "/", "http:", "", 693 },
	--Jira
	{ 0, 0, 0, 201, 43, "onjira.com", "/", "http:", "", 695 },
	--Kay Jewelers
	{ 0, 0, 0, 156, 26, "kay.com", "/", "http:", "", 698 },
	--Kmart
	{ 0, 0, 0, 157, 30, "kmart.com", "/", "http:", "", 702 },
	--Kogan Technologies
	{ 0, 0, 0, 158, 27, "kogan.com.au", "/", "http:", "", 703 },
	--Kohl's
	{ 0, 0, 0, 159, 45, "kohls.com", "/", "http:", "", 704 },
	--Kotaku
	{ 0, 0, 0, 199, 34, "kotaku.com", "/", "http:", "", 707 },
	--Launchpad
	{ 0, 0, 0, 203, 43, "launchpad.net", "/", "http:", "", 708 },
	--Lowe's
	{ 0, 0, 0, 160, 44, "lowes.com", "/", "http:", "", 722 },
	--Morgan Stanley
	{ 0, 0, 0, 128, 39, "morganstanley.co", "/", "http:", "", 738 },
	--Neckermann
	{ 0, 0, 0, 161, 45, "neckermann.de", "/", "http:", "", 750 },
	--Netflix
	{ 0, 0, 0, 162, 38, "netflix.com", "/", "http:", "", 756 },
	--Newegg
	{ 0, 0, 0, 163, 27, "newegg.com", "/", "http:", "", 759 },
	--Office Depot
	{ 0, 0, 0, 164, 24, "officedepot.co", "/", "http:", "", 768 },
	--oo.com.au
	{ 0, 0, 0, 165, 30, "oo.com.au", "/", "http:", "", 770 },
	--Overstock.com
	{ 0, 0, 0, 166, 30, "overstock.com", "/", "http:", "", 778 },
	--ProFlowers
	{ 0, 0, 0, 167, 25, "proflowers.com", "/", "http:", "", 793 },
	--QVC
	{ 0, 0, 0, 168, 45, "qvc.com", "/", "http:", "", 798 },
	--Redmine
	{ 0, 0, 0, 200, 43, "redmine.org", "/", "http:", "", 805 },
	--REI
	{ 0, 0, 0, 169, 29, "rei.com", "/", "http:", "", 806 },
	--Sam's Club
	{ 0, 0, 0, 171, 30, "samsclub.com", "/", "http:", "", 817 },
	--Schwab
	{ 0, 0, 0, 130, 39, "schwab.com", "/", "http:", "", 819 },
	--Sears
	{ 0, 0, 0, 172, 45, "sears.com", "/", "http:", "", 821 },
	--ShopNBC
	{ 0, 0, 0, 174, 45, "shopnbc.com", "/", "http:", "", 826 },
	--HP Home & Home Office Store
	{ 0, 0, 0, 153, 27, "shopping.hp.com", "/", "http:", "", 827 },
	--Staples
	{ 0, 0, 0, 175, 24, "staples.co", "/", "http:", "", 848 },
	--T. Rowe Price
	{ 0, 0, 0, 133, 39, "troweprice.com", "/", "http:", "", 855 },
	--Target
	{ 0, 0, 0, 176, 30, "target.com", "/", "http:", "", 858 },
	--Tchibo
	{ 0, 0, 0, 177, 45, "tchibo.de", "/", "http:", "", 859 },
	--TD Ameritrade
	{ 0, 0, 0, 111, 41, "tdameritrade.com", "/", "http:", "", 860 },
	--The Gap
	{ 0, 0, 0, 205, 32, "gap.com", "/", "http:", "", 863 },
	--The Sharper Image
	{ 0, 0, 0, 173, 27, "sharperimage.com", "/", "http:", "", 864 },
	--ThinkGeek
	--{ 0, 0, 0, 178, 45, "thinkgeek.com", "/", "http:", "", 865 },
	--Ticketmaster
	{ 0, 0, 0, 179, 31, "ticketmaster.com", "/", "http:", "", 867 },
	--Tickets.com
	{ 0, 0, 0, 180, 31, "tickets.com", "/", "http:", "", 868 },
	--Tiger Direct
	{ 0, 0, 0, 181, 27, "tigerdirect.com", "/", "http:", "", 871 },
	--Top Gear
	{ 0, 0, 0, 198, 35, "topgear.com", "/", "http:", "", 877 },
	--Trac
	{ 0, 0, 0, 202, 43, "trac.edgewall.org", "/", "http:", "", 878 },
	--Travelocity
	{ 0, 0, 0, 182, 37, "travelocity.co", "/", "http:", "", 880 },
	--Vanguard
	{ 0, 0, 0, 134, 39, "vanguard.co", "/", "http:", "", 885 },
	--vente-privee.com
	{ 0, 0, 0, 184, 32, "vente-privee.com", "/", "http:", "", 888 },
	--Victoria's Secret
	{ 0, 0, 0, 185, 32, "victoriassecret.com", "/", "http:", "", 892 },
	--Wachovia
	--{ 0, 0, 0, 135, 39, "wachovia.com", "/", "http:", "", 900 },
	--Walmart
	{ 0, 0, 0, 186, 30, "walmart.com", "/", "http:", "", 901 },
	--Wells Fargo
	{ 0, 0, 0, 136, 39, "wellsfargo.com", "/", "http:", "", 907 },
	--Windows Live SkyDrive
	{ 0, 0, 0, 132, 9, "skydrive.live.com", "/", "http:", "", 911 },
	--Woot
	{ 0, 0, 0, 188, 30, "woot.com", "/", "http:", "", 917 },
	--Zales
	{ 0, 0, 0, 189, 26, "zales.com", "/", "http:", "", 930 },
	--Zappos
	{ 0, 0, 0, 190, 32, "zappos.com", "/", "http:", "", 931 },
	--Salesforce.com
	{ 0, 0, 0, 129, 11, "salesforce.com", "/", "http:", "", 950 },
	--RitzCamera.com
	{ 0, 0, 0, 170, 27, "ritzcamera.com", "/", "http:", "", 951 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    gDetector:addHttpPattern(2, 5, 0, 327, 24, 0, 0, 'TDA/Flex_Application', 860)
    gDetector:addHttpPattern(2, 5, 0, 327, 24, 0, 0, 'TDA/Flex_Aapplication', 860)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end
    return gDetector
end

function DetectorClean()
end
