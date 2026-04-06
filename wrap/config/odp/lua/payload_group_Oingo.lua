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
detection_name: Payload Group "Oingo"
version: 15
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'WhereCoolThingsHappen' => 'Cool places and photos around the world.',
          'SugarSync' => 'Cloud-based backup service.',
          'Acrobat.com' => 'Adobe file transfer and PDF conversion site.',
          'Eclipse' => 'Software Updates for Eclipse.',
          'ZipCloud' => 'Cloud-based backup service.',
          'Redbox' => 'Online movie rental and video streaming.',
          'Podio' => 'Project Management software.',
          'Backupgrid' => 'Reseller of cloud backup / storage solutions.',
          'FiOS TV' => 'Verizon FiOS TV.',
          'LivePerson' => 'Online Marketing and Web analytics service provider.',
          'Cute Overload' => 'Pictures,videos and stories about Animals.',
          'JustCloud' => 'Cloud-based backup service.',
          'ZergNet' => 'Content aggregator for Sci-Fi Article.',
          'Vdio' => 'Web magazine.',
          'Minecraft' => 'Online game.',
          'iBackup' => 'Cloud-based backup service.',
          'Rotten Tomatoes' => 'Online information and reviews about new films.',
          'Constant Contact' => 'Online marketing service.',
          'Glympse' => 'Mobile App to share the location with others.',
          'TruuConfessions' => 'Online community for Confessions.',
          'Cheezburger' => 'Hang-out place for funny Photos and stories.',
          'H&R Block' => 'Tax service provider.',
          'theCHIVE' => 'Funny photos and videos.',
          'Bizrate' => 'Lists best deals for online shopping.',
          'Google Fiber' => 'Internet service provider by Google.',
          'Mention' => 'Site that will generate alerts and updates regarding topics you are interested in.',
          'Feedly' => 'News Aggregator.',
          'Carbonite' => 'Cloud-based backup service.',
          'King.com' => 'Web-based gaming.',
          'People Of Walmart' => 'Website for Walmart customer posted photos.',
          'Pivotal Tracker' => 'Project management and collaborative software.',
          'SOS Online Backup' => 'Cloud-based backup service.',
          'PubNub' => 'Cloud-based system for apps that require data to be pushed in real time.',
          'MyPCBackup' => 'Cloud-based backup service.',
          'MTv' => 'Official website for MTv.',
          'Amazon Ads System' => 'Amazon Ad services.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_Oingo",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Acrobat.com
	{ 0, 0, 0, 906, 22, "acrobat.com", "/", "http:", "", 1322 },
	--Eclipse
	{ 0, 0, 0, 907, 22, "eclipse.org", "/", "http:", "", 1413 },
	--King.com
	{ 0, 0, 0, 937, 20, "midasplayer.com", "/", "http:", "", 1599 },
	--Bizrate
	{ 0, 0, 0, 890, 22, "bizrate.com", "/", "http:", "", 1782 },
	--People Of Walmart
	{ 0, 0, 0, 891, 22, "peopleofwalmart.com", "/", "http:", "", 1783 },
	--Cute Overload
	{ 0, 0, 0, 892, 22, "cuteoverload.com", "/", "http:", "", 1784 },
	--Cheezburger
	{ 0, 0, 0, 893, 22, "cheezburger.com", "/", "http:", "", 1785 },
	--theCHIVE
	{ 0, 0, 0, 896, 22, "thechive.com", "/", "http:", "", 1788 },
	--TruuConfessions
	{ 0, 0, 0, 897, 22, "truuconfessions.com", "/", "http:", "", 1789 },
	--ZergNet
	{ 0, 0, 0, 898, 22, "zergnet.com", "/", "http:", "", 1790 },
	--WhereCoolThingsHappen
	{ 0, 0, 0, 899, 22, "wherecoolthingshappen.com", "/", "http:", "", 1791 },
	--H&R Block
	{ 0, 0, 0, 900, 22, "hrblock.com", "/", "http:", "", 1792 },
	--Constant Contact
	{ 0, 0, 0, 901, 22, "constantcontact.com", "/", "http:", "", 1793 },
	--Pivotal Tracker
	{ 0, 0, 0, 902, 22, "pivotaltracker.com", "/", "http:", "", 1794 },
	--Podio
	{ 0, 0, 0, 905, 22, "podio.com", "/", "http:", "", 1796 },
	--LivePerson
	{ 0, 0, 0, 908, 22, "liveperson.com", "/", "http:", "", 1797 },
	--Mention
	{ 0, 0, 0, 909, 22, "mention.net", "/", "http:", "", 1798 },
	--Feedly
	{ 0, 0, 0, 910, 22, "feedly.com", "/", "http:", "", 1799 },
	--Minecraft
	{ 0, 0, 0, 911, 22, "minecraft.net", "/", "http:", "", 1802 },
	--Rotten Tomatoes
	{ 0, 0, 0, 912, 22, "rottentomatoes.com", "/", "http:", "", 1803 },
	--Amazon Ads System
	{ 0, 0, 0, 913, 22, "amazon-adsystem.com", "/", "http:", "", 1804 },
	--MTv
	{ 0, 0, 0, 914, 22, "mtv.com", "/", "http:", "", 1805 },
	--Glympse
	{ 0, 0, 0, 916, 22, "glympse.com", "/", "http:", "", 1808 },
	--Backupgrid
	{ 0, 0, 0, 919, 9, "backupgrid.net", "/", "http:", "", 1812 },
	--Carbonite
	{ 0, 0, 0, 920, 9, "carbonite.com", "/", "http:", "", 1813 },
	--iBackup
	{ 0, 0, 0, 924, 9, "ibackup.com", "/", "http:", "", 1814 },
	--JustCloud
	{ 0, 0, 0, 921, 9, "justcloud.com", "/", "http:", "", 1815 },
	--MyPCBackup
	{ 0, 0, 0, 923, 9, "mypcbackup.com", "/", "http:", "", 1817 },
	--SOS Online Backup
	{ 0, 0, 0, 936, 9, "sosonlinebackup.com", "/", "http:", "", 1818 },
	--SugarSync
	{ 0, 0, 0, 925, 9, "sugarsync.com", "/", "http:", "", 1819 },
	--ZipCloud
	{ 0, 0, 0, 926, 9, "zipcloud.com", "/", "http:", "", 1820 },
	--PubNub
	{ 0, 0, 0, 927, 16, "pubnub.com", "/", "http:", "", 1822 },
	--FiOS TV
	{ 0, 0, 0, 932, 13, "tv.verizon.net", "/", "http:", "", 1827 },
	--Vdio
	{ 0, 0, 0, 933, 22, "vdio.com", "/", "http:", "", 1829 },
	--Redbox
	{ 0, 0, 0, 934, 22, "redbox.com", "/", "http:", "", 1830 },
	--Google Fiber
	{ 0, 0, 0, 935, 22, "fiber.google.com", "/", "http:", "", 1831 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    gDetector:addHttpPattern(2, 5, 0, 236, 21, 0, 0, 'CarboniteService', 1813, 1)
    gDetector:addHttpPattern(2, 5, 0, 238, 19, 0, 0, 'FiOS-Mercury', 1827); 
    --gDetector:addHttpPattern(2, 5, 0, 237, 19, 0, 0, 'WiiConnect24', 1823)
    gDetector:addHttpPattern(2, 5, 0, 296, 19, 0, 0, 'Chive/', 1788)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
