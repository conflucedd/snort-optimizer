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
detection_name: SSL Group "Zappa"
version: 19
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'AdGear' => 'Advertisement site.',
          'DioDeo' => 'Korean Entertainment news.',
          'TISTORY' => 'Korean Blog publishing service.',
          'Dropbox Upload' => 'File upload action of Dropbox.',
          'Shareman' => 'Traffic generated from chat and file transfer service by Shareman client.',
          'Mendeley' => 'A tool for sharing, storing, and organizing reference material such as PDFs.',
          'Crowd Science' => 'Advertisement site.',
          'AdXpose' => 'Advertisement site.',
          'Aliyun' => 'Chinese web portal.',
          'BlueKai' => 'Data-driven online marketing.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          'Adconion Media Group' => 'Multi-channel ad delivery company.',
          'Apple sites' => 'Apple corporate websites.',
          'Conduit' => 'Online website to create community toolbar.',
          'Verizon Media' => 'Advertisement site.',
          'Bazaarvoice' => 'Online service that provides data and analystics to brands/customer.',
          'Brighttalk' => 'Online webinar and video provider.',
          'Chango' => 'Advertisement site.',
          'Acrobat.com' => 'Adobe file transfer and PDF conversion site.',
          'Bloomberg' => 'Financial news and research.',
          'Answers.com' => 'A site that provides original answers to questions.',
          'Backblaze' => 'Online backup tool for Windows and Mac users.',
          'Atlas Advertiser Suite' => 'Tools for online advertising.',
          'Adtegrity' => 'Advertisement site.',
          'Astraweb' => 'A Usenet/newsgroup service provider.',
          'Blogger' => 'A blog publishing service owned by Google, formerly known as blogspot.',
          'Onehub' => 'A cloud storage provider.',
          'Bizo' => 'Advertisement site.',
          'Alibaba' => 'International trade site.',
          '12306.cn' => 'China Railway online customer service.',
          'ezhelp' => 'Allows remote access.',
          'AOL Ads' => 'AOL advertisement site.',
          'Admeld' => 'Ad delivery company servicing online publishers.',
          'Casale' => 'Advertisement site.',
          'Allegro.pl' => 'Polish auction website.',
          'Dropbox' => 'Cloud based file storage.',
          'AdRoll' => 'Online advertising and Retargetting website vistor.',
          'Connextra' => 'Advertisement site.',
          '4shared' => 'File sharing and storage service.',
          '17173.com' => 'Chinese social networking site.',
          'Bing' => 'Microsoft\'s internet search engine.',
          'Concur' => 'Business travel site.',
          'ClickBooth' => 'Advertisement site.',
          'Booking.com' => 'Online travel reservation site.',
          'AdReady' => 'Advertisement site.',
          'Bet365' => 'Online gambling website.',
          'Classmates' => 'Social networking site that allows schoolmates to connect via yearbook photograph.',
          'Criteo' => 'Advertisement site.',
          'Dropbox Download' => 'File download action of Dropbox.',
          'ADMETA' => 'Advertisement site.',
          'Connexity' => 'Advertisement site.',
          'DataLogicx' => 'Advertisement site.',
          'AD-X Tracking' => 'Data analysis and monitor ad related traffic tarfette for mobile application.',
          'Aggregate Knowledge' => 'Advertisement site.',
          'ADrive' => 'Online file storage and backup.',
          'ClickTale' => 'Advertisement site.',
          'Compete' => 'Data-driven marketing and advertising platform.',
          'Bild.de' => 'Online edition of German tabloid.',
          'AudienceScience' => 'Online marketing.',
          'Barnes and Noble' => 'Online retailer of books and other goods.',
          'Amazon' => 'Online retailer of books and most other goods.',
          'AppNexus' => 'Real-time advertising services.',
          'AdF.ly' => 'URL shortening service.',
          'eFax' => 'Internet fax service.',
          'Compuware' => 'Advertisement site.',
          'Commvault' => 'Enterprise data backup and storage management software.',
          'CBS' => 'CBS news website.',
          'cXense' => 'Advertisement site.',
          'Egloos' => 'Korean blog host.',
          'CloudFlare' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_zappa",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Answers.com
	{ 0, 1168, 'answers.com' },
	--Classmates
	{ 0, 1169, 'classmates.com' },
	--Apple sites
	{ 0, 1185, 'apple.com' },
	--Bild.de
	{ 0, 1196, 'bild.de' },
	--12306.cn
	{ 0, 1205, '12306.cn' },
	--Bet365
	{ 0, 1209, 'bet365.com' },
	--Brighttalk
	{ 0, 1211, 'brighttalk.com' },
	--Dropbox
	{ 0, 125, 'dropbox.com' },
	--AdF.ly
	{ 0, 1257, 'adf.ly' },
	--Bloomberg
	{ 0, 1259, 'bloomberg.com' },
	--Acrobat.com
	{ 0, 1322, 'acrobat.com' },
	--CBS
	{ 0, 1332, 'cbsnews.com' },
	--Conduit
	{ 0, 1375, 'conduit.com' },
	--ADrive
	{ 0, 17, 'adrive.com' },
	--CBS Interactive
	{ 0, 2354, 'cbspressexpress.com' },
	--17173.com
	{ 0, 2385, '17173.com' },
	--Alibaba
	{ 0, 2386, 'alibaba.com' },
	--Aliyun
	{ 0, 2389, 'aliyun.com' },
	--Amazon
	{ 0, 24, 'amazon.com' },
	--AppNexus
	{ 0, 2413, 'appnexus.com' },
	--Adconion Media Group
	{ 0, 2414, 'adconion.com' },
	--BlueKai
	{ 0, 2452, 'bluekai.com' },
	--Admeld
	{ 0, 2454, 'admeld.com' },
	--Atlas Advertiser Suite
	{ 0, 2456, 'atlassolutions.com' },
	--Compete
	{ 0, 2458, 'compete.com' },
	--AudienceScience
	{ 0, 2467, 'audiencescience.com' },
	--AdReady
	{ 0, 2497, 'adready.com' },
	--AdGear
	{ 0, 2500, 'adgear.com' },
	--ClickTale
	{ 0, 2502, 'clicktale.com' },
	--Casale
	{ 0, 2512, 'indexexchange.com' },
	--Chango
	{ 0, 2513, 'chango.com' },
	--Criteo
	{ 0, 2514, 'criteo.com' },
	--Connextra
	{ 0, 2529, 'connextra.com' },
	--CloudFlare
	{ 0, 2535, 'cloudflare.com' },
	--AdXpose
	{ 0, 2538, 'adxpose.com' },
	--DataLogicx
	{ 0, 2542, 'datalogix.com' },
	--Aggregate Knowledge
	{ 0, 2547, 'aggregateknowledge.com' },
	--Connexity
	{ 0, 2555, 'connexity.com' },
	--Bizo
	{ 0, 2557, 'bizo.com' },
	--Verizon Media
	{ 0, 2558, 'verizonmedia.com' },
	--ADMETA
	{ 0, 2569, 'admeta.com' },
	--cXense
	{ 0, 2572, 'cxense.com' },
	--Adtegrity
	{ 0, 2577, 'adtegrity.com' },
	--AOL Ads
	{ 0, 2578, 'advertising.aol.com' },
	--Compuware
	{ 0, 2579, 'compuware.com' },
	--ClickBooth
	{ 0, 2585, 'clickbooth.com' },
	--Crowd Science
	{ 0, 2591, 'yumenetworks.com' },
	--Booking.com
	{ 0, 2600, 'booking.com' },
	--Concur
	{ 0, 2601, 'concur.com' },
	--AdRoll
	{ 0, 2848, 'adroll.com' },
	--AD-X Tracking
	{ 0, 2850, 'adxtracking.com' },
	--Allegro.pl
	{ 0, 2851, 'allegro.pl' },
	--Dropbox Upload
	{ 0, 2895, 'block.dropbox.com' },
	--Dropbox Download
	{ 0, 2896, 'bolt.dropbox.com' },
	--Shareman
	{ 0, 2918, 'shareman.tv' },
	--Bazaarvoice
	{ 0, 2938, 'bazaarvoice.com' },
	--Mendeley
	{ 0, 3785, 'mendeley.com' },
	--Onehub
	{ 0, 3786, 'onehub.com' },
	--eFax
	{ 0, 3789, 'efax.com' },
	--TISTORY
	{ 0, 3798, 'tistory.com' },
	--DioDeo
	{ 0, 3799, 'diodeo.com' },
	--Astraweb
	{ 0, 38, 'astraweb.com' },
	--Egloos
	{ 0, 3800, 'egloos.com' },
	--ezhelp
	{ 0, 3803, 'ezhelp.co.kr' },
	--Backblaze
	{ 0, 47, 'backblaze.com' },
	--Barnes and Noble
	{ 0, 561, 'barnesandnoble.com' },
	--Blogger
	{ 0, 576, 'blogger.com' },
	--Bing
	{ 0, 58, 'bing.com' },
	--4shared
	{ 0, 948, '4shared.com' },
	--Commvault
	{ 0, 96, 'commvault.com' },
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
