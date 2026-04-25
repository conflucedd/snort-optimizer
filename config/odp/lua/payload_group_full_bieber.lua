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
detection_name: Payload Group Full "Bieber"
version: 29
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'The Gap' => 'Clothing and accessories retailer, encompassing Gap, Old Navy, Banana Republic, Piperlime, and Athleta.',
          'Jira' => 'Web based bug tracking and project management tool.',
          'Office Depot' => 'Office supply retailer.',
          'Tchibo' => 'German retailer with weekly changing products.',
          'Expedia' => 'Travel reservation website.',
          'Costco' => 'Warehouse club\'s online retail website.',
          'HP Home & Home Office Store' => 'HP\'s online store for computers and related products.',
          'Newegg' => 'Computer hardware and software retailer.',
          'HSBC' => 'Global banking and financial services company.',
          'Neckermann' => 'General goods online retailer.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'Travelocity' => 'Online travel agency.',
          'American Express' => 'Financial services company.',
          'Capital One' => 'U.S. based bank holding company.',
          'Sam\'s Club' => 'Warehouse club\'s online retail site.',
          'Walmart' => 'Discount department store.',
          'FogBugz' => 'Web-based project management and bug tracking system.',
          'Citi' => 'Financial services company.',
          'Basecamp' => 'Web based project management tool.',
          'Netflix' => 'Rental and on-demand internet television and movie streaming website.',
          'Discover' => 'Financial services company.',
          'Salesforce.com' => 'Enterprise cloud computing company.',
          'Bank of America' => 'Global financial services company.',
          'Sears' => 'Department store retailer.',
          'GoToMeeting' => 'Online meeting and desktop sharing service.',
          'QVC' => 'General shopping website in association with its related televised QVC broadcasts.',
          'Ticketmaster' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'Staples' => 'Office supply retailer.',
          'Lowe\'s' => 'Home improvement and appliance retailer.',
          'Vanguard' => 'Investment management company.',
          'Tiger Direct' => 'Online computer and electronics retailer.',
          'TD Ameritrade' => 'Online stock brokerage service.',
          'Blockbuster' => 'Movie and video game rental/streaming website.',
          'Fnac' => 'International retail chain focused on cultural and electronic products.',
          'Home Depot' => 'Retailer for home improvement and construction goods/products.',
          'Kogan Technologies' => 'Australian retailer of consumer electronic devices.',
          'Craigslist' => 'Popular online classifieds.',
          'GameStop' => 'Video game retailer.',
          'Crutchfield' => 'Electronics retailer.',
          'Bing' => 'Microsoft\'s internet search engine.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_bieber",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--FogBugz
	{ 0, 0, 0, 120, 43, "fogcreek.com", "/", "http:", "", 161 },
	--GoToMeeting
	{ 0, 0, 0, 124, 21, "gotomeeting.in", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.at", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.be", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.dk", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.fr", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.de", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.ie", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.se", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.ch", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeeting.com", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeet.com", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeet.at", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "gotomeet.me", "/", "http:", "", 187 },
	{ 0, 0, 0, 124, 21, "joingotomeeting.com", "/", "http:", "", 187 },
	--American Express
	{ 0, 0, 0, 110, 39, "americanexpress.ch", "/", "http:", "", 544 },
	{ 0, 0, 0, 110, 39, "americanexpress.kz", "/", "http:", "", 544 },
	{ 0, 0, 0, 110, 39, "americanexpress.be", "/", "http:", "", 544 },
	{ 0, 0, 0, 110, 39, "americanexpress.ae", "/", "http:", "", 544 },
	--Bank of America
	{ 0, 0, 0, 113, 39, "bac-assets.com", "/", "http:", "", 560 },
	--Basecamp
	{ 0, 0, 0, 204, 43, "basecamp.com", "/", "http:", "", 563 },
	--Blockbuster
	{ 0, 0, 0, 192, 38, "blockbuster.ca", "/", "http:", "", 575 },
	{ 0, 0, 0, 192, 38, "blockbusteronline.com.br", "/", "http:", "", 575 },
	--Bing
	{ 0, 0, 0, 114, 22, "bing.net", "/", "http:", "", 58 },
	{ 0, 0, 0, 114, 22, "www.bing.com", "/", "http:", "", 58 },
	--Capital One
	{ 0, 0, 0, 115, 39, "capitalone.ca", "/", "http:", "", 582 },
	--Citi
	{ 0, 0, 0, 116, 40, "citibank.com", "/", "http:", "", 590 },
	--Costco
	{ 0, 0, 0, 141, 30, "costco.ca", "/", "http:", "", 593 },
	--Craigslist
	{ 0, 0, 0, 206, 15, "craigslist.co", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.ca", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.de", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.gr", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.it", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.pl", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.pt", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.es", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.se", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.ch", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.hk", "/", "http:", "", 594 },
	{ 0, 0, 0, 206, 15, "craigslist.jp", "/", "http:", "", 594 },
	--Crutchfield
	{ 0, 0, 0, 142, 27, "crutchfield.ca", "/", "http:", "", 595 },
	--Discover
	{ 0, 0, 0, 117, 40, "discoverbank.com", "/", "http:", "", 615 },
	--Expedia
	{ 0, 0, 0, 147, 37, "expedia.at", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.be", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.ca", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.dk", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.fr", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.de", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.ie", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.it", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.nl", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.no", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.es", "/", "http:", "", 628 },
	{ 0, 0, 0, 147, 37, "expedia.se", "/", "http:", "", 628 },
	--Fidelity
	{ 0, 0, 0, 119, 39, "fidelity.at", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity.fr", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity.de", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity-italia.it", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity.nl", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fondosfidelity.es", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity.se", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity.co", "/", "http:", "", 636 },
	{ 0, 0, 0, 119, 39, "fidelity-international.com", "/", "http:", "", 636 },
	--{ 0, 0, 0, 119, 39, "fidelity.au", "/", "http:", "", 636 },
	--Fnac
	{ 0, 0, 0, 148, 45, "fnac.pt", "/", "http:", "", 640 },
	{ 0, 0, 0, 148, 45, "fnac.es", "/", "http:", "", 640 },
	{ 0, 0, 0, 148, 45, "fnac.ch", "/", "http:", "", 640 },
	--{ 0, 0, 0, 148, 45, "fnac.gr", "/", "http:", "", 640 },
	--{ 0, 0, 0, 148, 45, "fnac.it", "/", "http:", "", 640 },
	--GameStop
	{ 0, 0, 0, 122, 28, "gamestop.ca", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.fi", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.de", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.it", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.no", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.es", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.dk", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.ie", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.pt", "/", "http:", "", 650 },
	{ 0, 0, 0, 122, 28, "gamestop.se", "/", "http:", "", 650 },
	--Home Depot
	{ 0, 0, 0, 152, 44, "homedepot.ca", "/", "http:", "", 670 },
	--HSBC
	{ 0, 0, 0, 125, 39, "hsbc.am", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.bm", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.ca", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.ky", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.cz", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.fr", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbctrinkaus.de", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.ge", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.gr", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.ie", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.kz", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.pl", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.ru", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.lk", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.ae", "/", "http:", "", 675 },
	{ 0, 0, 0, 125, 39, "hsbc.es", "/", "http:", "", 675 },
	--Jira
	{ 0, 0, 0, 201, 43, "jira.com", "/", "http:", "", 695 },
	{ 0, 0, 0, 201, 43, "jira.atlassian.com", "/", "http:", "", 695 },
	--Kogan Technologies
	{ 0, 0, 0, 158, 27, "kogan.co.uk", "/", "http:", "", 703 },
	--LBPS (Deprecated)
	--{ 0, 0, 0, 127, 39, "lbps.com", "/", "http:", "", 709 },
	--Lowe's
	{ 0, 0, 0, 160, 44, "lowes.ca", "/", "http:", "", 722 },
	--Neckermann
	{ 0, 0, 0, 161, 45, "neckermann.at", "/", "http:", "", 750 },
	{ 0, 0, 0, 161, 45, "neckermann.ch", "/", "http:", "", 750 },
	{ 0, 0, 0, 161, 45, "neckermann.cz", "/", "http:", "", 750 },
	{ 0, 0, 0, 161, 45, "neckermann.sk", "/", "http:", "", 750 },
	{ 0, 0, 0, 161, 45, "neckermann.si", "/", "http:", "", 750 },
	{ 0, 0, 0, 161, 45, "neckermann.com.pl", "/", "http:", "", 750 },
	{ 0, 0, 0, 161, 45, "neck.nl", "/", "http:", "", 750 },
	--{ 0, 0, 0, 161, 45, "neckermann.ua", "/", "http:", "", 750 },
	--{ 0, 0, 0, 161, 45, "neckermann.hr", "/", "http:", "", 750 },
	--{ 0, 0, 0, 161, 45, "neck.be", "/", "http:", "", 750 },
	--Netflix
	{ 0, 0, 0, 162, 38, "nflximg.net", "/", "http:", "", 756 },
	{ 0, 0, 0, 162, 38, "nflximg.com", "/", "http:", "", 756 },
	--Newegg
	{ 0, 0, 0, 163, 27, "newegg.ca", "/", "http:", "", 759 },
	{ 0, 0, 0, 163, 27, "newegg.cn", "/", "http:", "", 759 },
	{ 0, 0, 0, 163, 27, "newegg.com.tw", "/", "http:", "", 759 },
	{ 0, 0, 0, 163, 27, "neweggflash.com", "/", "http:", "", 759 },
	{ 0, 0, 0, 163, 27, "neweggbusiness.com", "/", "http:", "", 759 },
	--Office Depot
	{ 0, 0, 0, 164, 24, "officedepot.at", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.be", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.ca", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.cz", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.eu", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.fr", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.de", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.hu", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.lu", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.pl", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.sk", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.es", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.ch", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "officedepot.it", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "office-depot.be", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "office-depot.fr", "/", "http:", "", 768 },
	{ 0, 0, 0, 164, 24, "office-depot.ch", "/", "http:", "", 768 },
	--{ 0, 0, 0, 164, 24, "officedepot.cn", "/", "http:", "", 768 },
	--{ 0, 0, 0, 164, 24, "officedepot.ie", "/", "http:", "", 768 },
	--QVC
	{ 0, 0, 0, 168, 45, "qvc.de", "/", "http:", "", 798 },
	{ 0, 0, 0, 168, 45, "qvc.it", "/", "http:", "", 798 },
	{ 0, 0, 0, 168, 45, "qvc.jp", "/", "http:", "", 798 },
	{ 0, 0, 0, 168, 45, "qvcuk.com", "/", "http:", "", 798 },
	--Sam's Club
	{ 0, 0, 0, 171, 30, "sams.com.mx", "/", "http:", "", 817 },
	{ 0, 0, 0, 171, 30, "samsclubpr.com", "/", "http:", "", 817 },
	--Sears
	{ 0, 0, 0, 172, 45, "sears.ca", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searspartsdirect.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searshomeservices.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searscommerceservices.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsflowers.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsgaragedoors.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searshomeapplianceshowroom.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searshomepro.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searshometownstores.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsoptical.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsoutlet.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsdrivingschools.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsvacations.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searshardwarestores.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searscommercial.com", "/", "http:", "", 821 },
	{ 0, 0, 0, 172, 45, "searsvehicleprotectionplan.com", "/", "http:", "", 821 },
	--HP Home & Home Office Store
	{ 0, 0, 0, 153, 27, "store.hp.com", "/", "http:", "", 827 },
	--Staples
	{ 0, 0, 0, 175, 24, "staples.ca", "/", "http:", "", 848 },
	{ 0, 0, 0, 175, 24, "staples.pt", "/", "http:", "", 848 },
	{ 0, 0, 0, 175, 24, "staples.de", "/", "http:", "", 848 },
	{ 0, 0, 0, 175, 24, "staples.com", "/", "http:", "", 848 },
	--Tchibo
	{ 0, 0, 0, 177, 45, "tchibo.ch", "/", "http:", "", 859 },
	{ 0, 0, 0, 177, 45, "tchibo.pl", "/", "http:", "", 859 },
	{ 0, 0, 0, 177, 45, "tchibo.cz", "/", "http:", "", 859 },
	{ 0, 0, 0, 177, 45, "tchibo.com.tr", "/", "http:", "", 859 },
	{ 0, 0, 0, 177, 45, "eduscho.at", "/", "http:", "", 859 },
	--TD Ameritrade
	{ 0, 0, 0, 111, 41, "amtd.com", "/", "http:", "", 860 },
	--{ 0, 0, 0, 111, 41, "tdameritrade-st.streamer.com", "/", "http:", "", 860 },
	--The Gap
	{ 0, 0, 0, 205, 32, "gapcanada.ca", "/", "http:", "", 863 },
	{ 0, 0, 0, 205, 32, "gap.cn", "/", "http:", "", 863 },
	{ 0, 0, 0, 205, 32, "gap.eu", "/", "http:", "", 863 },
	{ 0, 0, 0, 205, 32, "gap.co.jp", "/", "http:", "", 863 },
	--Ticketmaster
	{ 0, 0, 0, 179, 31, "ticketmaster.ca", "/", "http:", "", 867 },
	{ 0, 0, 0, 179, 31, "ticketsnow.com", "/", "http:", "", 867 },
	--Tiger Direct
	{ 0, 0, 0, 181, 27, "tigerdirect.ca", "/", "http:", "", 871 },
	--Travelocity
	{ 0, 0, 0, 182, 37, "travelocity.ca", "/", "http:", "", 880 },
	{ 0, 0, 0, 182, 37, "travelocity.co.uk", "/", "http:", "", 880 },
	{ 0, 0, 0, 182, 37, "travelocity.com", "/", "http:", "", 880 },
	{ 0, 0, 0, 182, 37, "tvlcdn.com", "/", "http:", "", 880 },
	--Vanguard
	{ 0, 0, 0, 134, 39, "vanguardinvestments.dk", "/", "http:", "", 885 },
	{ 0, 0, 0, 134, 39, "vanguardinvestments.de", "/", "http:", "", 885 },
	{ 0, 0, 0, 134, 39, "vanguardinvestments.nl", "/", "http:", "", 885 },
	{ 0, 0, 0, 134, 39, "vanguardinvestments.se", "/", "http:", "", 885 },
	{ 0, 0, 0, 134, 39, "vanguardinvestments.ch", "/", "http:", "", 885 },
	{ 0, 0, 0, 134, 39, "vanguardjapan.co.jp", "/", "http:", "", 885 },
	--{ 0, 0, 0, 134, 39, "vanguardinvestments.fr", "/", "http:", "", 885 },
	--Walmart
	{ 0, 0, 0, 186, 30, "walmart.ca", "/", "http:", "", 901 },
	--Salesforce.com
	{ 0, 0, 0, 129, 11, "mybuys.com", "/", "http:", "", 950 },
	{ 0, 0, 0, 129, 11, "evergage.com", "/", "http:", "", 950 },
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
