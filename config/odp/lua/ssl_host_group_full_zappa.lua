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
detection_name: SSL Group Full "Zappa"
version: 20
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Concur' => 'Business travel site.',
          'Verizon Media' => 'Advertisement site.',
          'Bing' => 'Microsoft\'s internet search engine.',
          'Casale' => 'Advertisement site.',
          'Conduit' => 'Online website to create community toolbar.',
          'Bloomberg' => 'Financial news and research.',
          'Dropbox' => 'Cloud based file storage.',
          'Blogger' => 'A blog publishing service owned by Google, formerly known as blogspot.',
          'AD-X Tracking' => 'Data analysis and monitor ad related traffic tarfette for mobile application.',
          'AppNexus' => 'Real-time advertising services.',
          'Apple sites' => 'Apple corporate websites.',
          'Bizo' => 'Advertisement site.',
          'Booking.com' => 'Online travel reservation site.',
          'Amazon' => 'Online retailer of books and most other goods.',
          'Bet365' => 'Online gambling website.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          'Dropbox Download' => 'File download action of Dropbox.',
          'Dropbox Upload' => 'File upload action of Dropbox.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_zappa",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Apple sites
	{ 0, 1185, 'cdn-apple.com' },
	{ 0, 1185, 'apple-mapkit.com' },
	{ 0, 1185, 'apple-darwin.net' },
	{ 0, 1185, 'applereach.net' },
	{ 0, 1185, 'calendarserver.org' },
	{ 0, 1185, 'cups.org' },
	{ 0, 1185, 'desktopmovie.net' },
	{ 0, 1185, 'dvdstudiopro.info' },
	{ 0, 1185, 'dvdstudiopro.net' },
	{ 0, 1185, 'imac-apple.com' },
	{ 0, 1185, 'iwork.com' },
	{ 0, 1185, 'myapple.net' },
	{ 0, 1185, 'playquicktime.com' },
	{ 0, 1185, 'publishing-research.org' },
	{ 0, 1185, 'publishingsurvey.org' },
	{ 0, 1185, 'quicktime.cc' },
	{ 0, 1185, 'rip-mix-burn.com' },
	{ 0, 1185, 'ripmixburn.com' },
	{ 0, 1185, 'thinkdifferent.com' },
	{ 0, 1185, 'xserve.com' },
	--Bet365
	{ 0, 1209, 'bet365careers.com' },
	--Dropbox
	{ 0, 125, 'cfl.dropboxstatic.com' },
	{ 0, 125, 'dl.dropboxusercontent.com' },
	--Bloomberg
	{ 0, 1259, 'bloomberg.net' },
	{ 0, 1259, 'bna.com' },
	{ 0, 1259, 'bgov.com' },
	{ 0, 1259, 'bloombergview.com' },
	{ 0, 1259, 'businessweek.com' },
	{ 0, 1259, 'bloombergtradebook.com' },
	{ 0, 1259, 'bloombergbriefs.com' },
	{ 0, 1259, 'bloombergindexes.com' },
	{ 0, 1259, 'bloombergsef.com' },
	{ 0, 1259, 'bloomberglaw.com' },
	{ 0, 1259, 'bloomberglink.com' },
	{ 0, 1259, 'bloombergsports.com' },
	{ 0, 1259, 'newenergyfinance.com' },
	{ 0, 1259, 'bloombergbnef.sc.omtrdc.net' },
	{ 0, 1259, 'assets.bwbx.io' },
	{ 0, 1259, 'bnef.com' },
	{ 0, 1259, 'bloomberg.tv' },
	{ 0, 1259, 'bloomberg.fm' },
	{ 0, 1259, 'blpprofessional.com' },
	{ 0, 1259, 'bloomberglp.com' },
	{ 0, 1259, 'bloomberglive.com' },
	--Conduit
	{ 0, 1375, 'como.com' },
	--CBS Interactive
	{ 0, 2354, 'cbsi.secure.force.com' },
	--Amazon
	{ 0, 24, 'amazon.jobs' },
	{ 0, 24, 'amazon.in' },
	{ 0, 24, 'amazon.es' },
	{ 0, 24, 'amazon.de' },
	{ 0, 24, 'amazon.co.uk' },
	{ 0, 24, 'amazon.co.jp' },
	{ 0, 24, 'amazon.ca' },
	{ 0, 24, 'm.media-amazon.com' },
	--AppNexus
	{ 0, 2413, 'alenty.com' },
	--Casale
	{ 0, 2512, 'medianet.com' },
	--Bizo
	{ 0, 2557, 'bizographics.com' },
	--Verizon Media
	{ 0, 2558, 'brightroll.com' },
	--Booking.com
	{ 0, 2600, 'workingatbooking.com' },
	--Concur
	{ 0, 2601, 'concur.de' },
	{ 0, 2601, 'concur.ca' },
	{ 0, 2601, 'concur.nl' },
	{ 0, 2601, 'concur.fr' },
	{ 0, 2601, 'concur.co.uk' },
	{ 0, 2601, 'concur.co.in' },
	{ 0, 2601, 'concur.co.jp' },
	--AD-X Tracking
	{ 0, 2850, 'ad-x.co.uk' },
	--Dropbox Upload
	{ 0, 2895, 'com-dbox.netmng.com' },
	{ 0, 2895, 'dl-web.dropbox.com' },
	{ 0, 2895, 'dboxsnapengage.com' },
	{ 0, 2895, 'snapengage.dropbox.com' },
	--Dropbox Download
	{ 0, 2896, 'dropboxstatic.com' },
	--Blogger
	{ 0, 576, 'blogspot.com' },
	--Bing
	{ 0, 58, 'bing.net' },
}
function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end
    return gDetector
end

function DetectorClean()
end
