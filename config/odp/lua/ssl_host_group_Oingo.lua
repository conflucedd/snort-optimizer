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
detection_name: SSL Group "Oingo"
version: 22
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Redbox' => 'Online movie rental and video streaming.',
          'Xbox Live' => 'Microsoft online gaming service.',
          'Microsoft' => 'Official Microsoft website.',
          'Java Update' => 'Java update software service.',
          'Backupgrid' => 'Reseller of cloud backup / storage solutions.',
          'Vdio' => 'Web magazine.',
          'ESPN' => 'Online Sports news and show.',
          'SOS Online Backup' => 'Cloud-based backup service.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'Chartbeat' => 'Realtime Website data for Collection.',
          'SoftEther' => 'An open source VPN.',
          'TweetDeck' => 'Dashboard application to manage both Twitter and Facebook.',
          'Sourcefire.com' => 'Company website for Network security and Intrusion Detection engine.',
          'Rotten Tomatoes' => 'Online information and reviews about new films.',
          'Flipboard' => 'News aggregator Mobile application.',
          'Microsoft Update' => 'Microsoft software updates.',
          'JustCloud' => 'Cloud-based backup service.',
          'Basecamp' => 'Web based project management tool.',
          'Minecraft' => 'Online game.',
          'MyPCBackup' => 'Cloud-based backup service.',
          'ZipCloud' => 'Cloud-based backup service.',
          'iBackup' => 'Cloud-based backup service.',
          'Glympse' => 'Mobile App to share the location with others.',
          'Pivotal Tracker' => 'Project management and collaborative software.',
          'ShareThis' => 'Social advertising widgets.',
          'Podio' => 'Project Management software.',
          'Disney' => 'Official Disney website.',
          'Google Fiber' => 'Internet service provider by Google.',
          'LivePerson' => 'Online Marketing and Web analytics service provider.',
          'Carbonite' => 'Cloud-based backup service.',
          'H&R Block' => 'Tax service provider.',
          'Mailbox' => 'App for Email service.',
          'Mention' => 'Site that will generate alerts and updates regarding topics you are interested in.',
          'SugarSync' => 'Cloud-based backup service.',
          'FiOS TV' => 'Verizon FiOS TV.',
          'Constant Contact' => 'Online marketing service.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_Oingo",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--TweetDeck
	{ 0, 1360, 'tweetdeck.com' },
	--ESPN
	{ 0, 1364, 'espn.go.com' },
	--Sourcefire.com
	{ 0, 1398, 'sourcefire.com' },
	--Flipboard
	{ 1, 1402, 'flipboard.com' },
	--Microsoft
	{ 0, 1423, 'microsoft.com' },
	--Chartbeat
	{ 0, 1460, 'chartbeat.net' },
	--Disney
	{ 0, 1515, 'disney.go.com' },
	--Java Update
	{ 1, 1569, 'java.com' },
	--H&R Block
	{ 0, 1792, 'hrblock.com' },
	--Constant Contact
	{ 0, 1793, 'constantcontact.com' },
	--Pivotal Tracker
	{ 0, 1794, 'pivotaltracker.com' },
	--Podio
	{ 0, 1796, 'podio.com' },
	--LivePerson
	{ 0, 1797, 'liveperson.net' },
	--Mention
	{ 1, 1798, 'mention.net' },
	--Mailbox
	{ 1, 1801, 'orcali.com' },
	--Minecraft
	{ 0, 1802, 'minecraft.net' },
	--Rotten Tomatoes
	{ 0, 1803, 'rottentomatoes.com' },
	--Glympse
	{ 1, 1808, 'glympse.com' },
	--Backupgrid
	{ 0, 1812, 'backupgrid.net' },
	--Carbonite
	{ 0, 1813, 'carbonite.com' },
	--iBackup
	{ 0, 1814, 'ibackup.com' },
	--JustCloud
	{ 0, 1815, 'justcloud.com' },
	--MyPCBackup
	{ 0, 1817, 'mypcbackup.com' },
	--SOS Online Backup
	{ 0, 1818, 'sosonlinebackup.com' },
	--SugarSync
	{ 0, 1819, 'sugarsync.com' },
	--ZipCloud
	{ 0, 1820, 'zipcloud.com' },
	--FiOS TV
	{ 0, 1827, 'tv.verizon.net' },
	--Vdio
	{ 0, 1829, 'vdio.com' },
	--Redbox
	{ 0, 1830, 'redbox.com' },
	--Google Fiber
	{ 0, 1831, 'fiber.google.com' },
	--ShareThis
	{ 0, 2635, 'sharethis.com' },
	--SoftEther
	{ 1, 3809, 'softether.org' },
	--Basecamp
	{ 0, 563, 'basecamp.com' },
	--Microsoft Update
	{ 0, 731, 'update.microsoft.com' },
	--Xbox Live
	{ 0, 921, 'xbox.com' },
	--Habbo
	{ 0, 980, 'habbo.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end
    return gDetector
end

function DetectorClean()
end
