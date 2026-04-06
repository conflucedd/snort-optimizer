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
detection_name: Payload Group "Clash"
version: 30
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Imgur' => 'Image hosting website.',
          'NewsNow' => 'News aggregator website that links to thousands of publications.',
          'CheapTickets' => 'Travel services company focused on the leisure market.',
          'Saks Fifth Avenue' => 'Luxury, high-end specialty store.',
          'Game Informer' => 'Video game news, reviews, and previews website.',
          'REVOLVEclothing' => 'Designer clothing and accessories retailer.',
          'Lord & Taylor' => 'Specialty-retail department store chain.',
          'House of Fraser' => 'British department store.',
          'Renren' => 'Chinese social networking site.',
          'Bluefly' => 'Online fashion retailer.',
          'Sports Authority' => 'Sporting goods retailer.',
          'Qzone' => 'Chinese social networking site.',
          'imo.im' => 'Instant messenger service for various instant messaging protocols.',
          'Haiku Learning Systems' => 'Online tool for teaching and learning.',
          'Google Drive' => 'A free office suite and cloud storage system hosted by Google.',
          'Ace Hardware Corporation' => 'Home improvement goods and hardware retailer.',
          'MediaFire' => 'File and image hosting site.',
          'ImageShack' => 'Image hosting website.',
          'Google News' => 'Automated news aggregator.',
          'GameSpy' => 'Video game news, reviews, and previews website.',
          'Collabedit' => 'Online collaborative code editor which allows multiple users to modify/view code together.',
          'Blue Nile' => 'Online jewelry and diamonds retailer.',
          'Veoh' => 'Internet television and video sharing service.',
          'Menards' => 'Home improvement goods retailer.',
          'G4' => 'Video game news website to accompany its associated television channel.',
          'Addicting Games' => 'Website for flash games.',
          'Delicious' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          'Netlog' => 'Social networking site geared towards European youth.',
          'Vimeo' => 'Website for viewing and sharing videos.',
          'Black & Decker Corporation' => 'Power tools, hardware, and home improvement products retailer.',
          'Quill Corporation' => 'Mail-order office supply retailer.',
          'Barneys New York' => 'Luxury retail department store.',
          'StubHub' => 'Website for buying and selling tickets for sports, concerts, and other events.',
          'Metacafe' => 'Online video entertainment website.',
          'Zip.ca' => 'Online DVD rental company based in Canada.',
          'Bloomingdales' => 'Retail department store.',
          'Kongregate' => 'Website for hosting and playing games.',
          'Blip.tv' => 'Online video streaming site for web series.',
          'Rona' => 'Hardware, home improvement, and gardening products retailer based in Canada.',
          'Newsvine' => 'Community based collaborative news website.',
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.',
          '6.pm' => 'Discount shoes and clothing retailer.',
          'David Jones' => 'High-end Australian department store.',
          'OfficeMax' => 'Office supplies retailer.',
          'ShopStyle' => 'Fashion search engine which links to various retailers.',
          'Neiman Marcus' => 'Luxury retail department store.',
          'GameTrailers' => 'Video game news, reviews, and previews website.',
          'Urban Outfitters' => 'Clothing and footwear retailer.',
          'Box' => 'File storage and transfer site.',
          'CC Studios' => 'Entertainment website focused on film and animation.',
          'myUdutu' => 'Online course authoring tool.',
          'Voyages-sncf.com' => 'Travel agency website.',
          'Nordstrom' => 'Retail department store.',
          'deviantART' => 'Online community focused around artwork.',
          'TripAdvisor' => 'Travel services site for information and reviews regarding travel related content.',
          'Shoplet' => 'Office products retailer.',
          'PopUrls' => 'Website that aggregates headlines from various popular social news sites and portals.',
          'ShowDocument' => 'Web application that allows users to collaborate on and review documents in real time.',
          'Orbitz' => 'Internet based travel services company.',
          'Macy\'s' => 'Department store chain.',
          'Diigo' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          'City Sports' => 'Sporting goods and athletic apparel retailer.',
          'Web Of Trust' => 'Community-based website reputation rating tool.',
          'Destructoid' => 'An independent blog focused on video games.',
          'Tiffany & Co.' => 'Jewelry and silverware retailer.',
          'TinyPic' => 'Photo and video sharing service.',
          'WiZiQ' => 'Online learning tool meant to provide a virtual classroom environment.',
          'Dillards' => 'Retail department store.',
          'Swarovski' => 'Retailer for jewelry and other related luxury products.',
          'Joystiq' => 'Video gaming blog.',
          'ShowClix' => 'A full-service ticketing company.',
          'PopCap Games' => 'Online games website.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_clash",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Box
	{ 0, 0, 0, 217, 9, "box.net", "/", "http:", "", 1326 },
	--Flickr
	{ 0, 0, 0, 225, 5, "flickr.com", "/", "http:", "", 159 },
	--Google Drive
	{ 0, 0, 0, 285, 11, "docs.google.com", "/", "http:", "", 180 },
	--MediaFire
	{ 0, 0, 0, 243, 9, "mediafire.com", "/", "http:", "", 285 },
	--6.pm
	{ 0, 0, 0, 207, 32, "6pm.com", "/", "http:", "", 538 },
	--Ace Hardware Corporation
	{ 0, 0, 0, 208, 44, "acehardware.com", "/", "http:", "", 539 },
	--Addicting Games
	{ 0, 0, 0, 209, 20, "addictinggames.com", "/", "http:", "", 540 },
	--CC Studios
	{ 0, 0, 0, 210, 13, "cc.com", "/short-form", "http:", "", 556 },
	--Barneys New York
	{ 0, 0, 0, 211, 45, "barneys.com", "/", "http:", "", 562 },
	--Black & Decker Corporation
	{ 0, 0, 0, 212, 44, "blackanddecker.com", "/", "http:", "", 572 },
	--Blip.tv
	{ 0, 0, 0, 213, 13, "blip.tv", "/", "http:", "", 574 },
	--Bloomingdales
	{ 0, 0, 0, 214, 45, "bloomingdales.com", "/", "http:", "", 577 },
	--Blue Nile
	{ 0, 0, 0, 216, 26, "bluenile.com", "/", "http:", "", 578 },
	--Bluefly
	{ 0, 0, 0, 215, 32, "bluefly.com", "/", "http:", "", 579 },
	--CheapTickets
	{ 0, 0, 0, 218, 31, "cheaptickets.com", "/", "http:", "", 588 },
	--City Sports
	{ 0, 0, 0, 219, 29, "citysports.com", "/", "http:", "", 591 },
	--Collabedit
	{ 0, 0, 0, 286, 8, "collabedit.com", "/", "http:", "", 592 },
	--David Jones
	{ 0, 0, 0, 220, 45, "davidjones.com.au", "/", "http:", "", 601 },
	--Delicious
	{ 0, 0, 0, 221, 14, "delicious.com", "/", "http:", "", 605 },
	--Destructoid
	{ 0, 0, 0, 222, 34, "destructoid.com", "/", "http:", "", 607 },
	--deviantART
	{ 0, 0, 0, 287, 5, "deviantart.com", "/", "http:", "", 608 },
	--Diigo
	{ 0, 0, 0, 223, 14, "diigo.com", "/", "http:", "", 612 },
	--Dillards
	{ 0, 0, 0, 224, 45, "dillards.com", "/", "http:", "", 613 },
	--G4
	{ 0, 0, 0, 226, 34, "g4tv.com", "/", "http:", "", 646 },
	--Game Informer
	{ 0, 0, 0, 227, 34, "gameinformer.com", "/", "http:", "", 647 },
	--GameSpy
	{ 0, 0, 0, 228, 34, "gamespy.com", "/", "http:", "", 649 },
	--GameTrailers
	{ 0, 0, 0, 229, 34, "gametrailers.com", "/", "http:", "", 651 },
	--Google News
	{ 0, 0, 0, 230, 33, "news.google.", "/", "http:", "", 663 },
	--Haiku Learning Systems
	{ 0, 0, 0, 231, 12, "haikulearning.com", "/", "http:", "", 669 },
	--House of Fraser
	{ 0, 0, 0, 233, 45, "houseoffraser.co.uk", "/", "http:", "", 674 },
	--ImageShack
	{ 0, 0, 0, 235, 9, "imageshack.us", "/", "http:", "", 682 },
	--Imgur
	{ 0, 0, 0, 236, 9, "imgur.com", "/", "http:", "", 684 },
	--imo.im
	{ 0, 0, 0, 237, 10, "imo.im", "/", "http:", "", 685 },
	--Joystiq
	{ 0, 0, 0, 238, 34, "joystiq.com", "/", "http:", "", 696 },
	--Kongregate
	{ 0, 0, 0, 239, 20, "kongregate.com", "/", "http:", "", 705 },
	--Lord & Taylor
	{ 0, 0, 0, 240, 45, "lordandtaylor.com", "/", "http:", "", 719 },
	--Menards
	{ 0, 0, 0, 245, 44, "menards.com", "/", "http:", "", 727 },
	--Metacafe
	{ 0, 0, 0, 246, 13, "metacafe.com", "/", "http:", "", 728 },
	--myUdutu
	{ 0, 0, 0, 274, 12, "myudutu.com", "/", "http:", "", 748 },
	--Neiman Marcus
	{ 0, 0, 0, 249, 45, "neimanmarcus.com", "/", "http:", "", 751 },
	--Netlog
	{ 0, 0, 0, 290, 5, "netlog.com", "/", "http:", "", 757 },
	--NewsNow
	{ 0, 0, 0, 250, 33, "newsnow.co.uk", "/", "http:", "", 760 },
	--Newsvine
	{ 0, 0, 0, 251, 14, "newsvine.com", "/", "http:", "", 761 },
	--Nordstrom
	{ 0, 0, 0, 252, 45, "nordstrom.com", "/", "http:", "", 764 },
	--OfficeMax
	{ 0, 0, 0, 253, 24, "officemax.com", "/", "http:", "", 769 },
	--Orbitz
	{ 0, 0, 0, 254, 37, "orbitz.com", "/", "http:", "", 775 },
	--PopCap Games
	{ 0, 0, 0, 256, 20, "popcap.co", "/", "http:", "", 789 },
	--PopUrls
	{ 0, 0, 0, 257, 33, "popurls.com", "/", "http:", "", 790 },
	--Quill Corporation
	{ 0, 0, 0, 260, 24, "quill.com", "/", "http:", "", 797 },
	--Qzone
	{ 0, 0, 0, 288, 5, "qzone.qq.com", "/", "http:", "", 799 },
	--Renren
	{ 0, 0, 0, 289, 5, "renren.com", "/", "http:", "", 808 },
	--REVOLVEclothing
	{ 0, 0, 0, 261, 32, "revolveclothing.com", "/", "http:", "", 809 },
	--Rona
	{ 0, 0, 0, 262, 44, "rona.ca", "/", "http:", "", 810 },
	--Saks Fifth Avenue
	{ 0, 0, 0, 263, 45, "saksfifthavenue.com", "/", "http:", "", 816 },
	--Shoplet
	{ 0, 0, 0, 264, 24, "shoplet.com", "/", "http:", "", 825 },
	--ShopStyle
	{ 0, 0, 0, 265, 32, "shopstyle.co", "/", "http:", "", 828 },
	--ShowClix
	{ 0, 0, 0, 266, 31, "showclix.com", "/", "http:", "", 830 },
	--ShowDocument
	{ 0, 0, 0, 284, 8, "showdocument.co", "/", "http:", "", 831 },
	--Sports Authority
	{ 0, 0, 0, 267, 29, "sportsauthority.com", "/", "http:", "", 842 },
	--StubHub
	{ 0, 0, 0, 268, 31, "stubhub.com", "/", "http:", "", 850 },
	--Swarovski
	{ 0, 0, 0, 269, 26, "swarovski.com", "/", "http:", "", 854 },
	--Tiffany & Co.
	{ 0, 0, 0, 271, 26, "tiffany.com", "/", "http:", "", 870 },
	--TinyPic
	{ 0, 0, 0, 272, 9, "tinypic.com", "/", "http:", "", 873 },
	--TripAdvisor
	{ 0, 0, 0, 273, 37, "tripadvisor.com", "/", "http:", "", 881 },
	--Urban Outfitters
	{ 0, 0, 0, 275, 32, "urbanoutfitters.co", "/", "http:", "", 883 },
	--Veoh
	{ 0, 0, 0, 276, 13, "veoh.co", "/", "http:", "", 889 },
	--Vimeo
	{ 0, 0, 0, 277, 13, "vimeo.com", "/", "http:", "", 893 },
	--Voyages-sncf.com
	{ 0, 0, 0, 278, 37, "voyages-sncf.com", "/", "http:", "", 899 },
	--Web Of Trust
	{ 0, 0, 0, 279, 18, "mywot.com", "/", "http:", "", 903 },
	--WiZiQ
	{ 0, 0, 0, 280, 12, "wiziq.com", "/", "http:", "", 914 },
	--Zip.ca
	{ 0, 0, 0, 281, 38, "zip.ca", "/", "http:", "", 932 },
	--Macy's
	{ 0, 0, 0, 242, 45, "macys.com", "/", "http:", "", 952 },
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
