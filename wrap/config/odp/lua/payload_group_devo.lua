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
detection_name: Payload Group "Devo"
version: 43
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'CiteULike' => 'Social bookmarking-esque site for scholarly papers and references.',
          'AutoZone' => 'Automotive parts and accessories retailer.',
          'Tesco.com' => 'General E-commerce website.',
          'Mister Wong' => 'European social bookmarking service.',
          'folkd' => 'Social bookmarking and social news website.',
          'Hushmail' => 'Web mail service providing encrypted and virus scanned e-mail.',
          'Tudou' => 'Popular Chinese video sharing website.',
          'Clarizen' => 'Work management and project management system.',
          'TransferBigFiles.com' => 'File hosting and sharing service.',
          'GMX Mail' => 'German based webmail service.',
          'Tinychat' => 'Web chat service with both instant messaging and video chat.',
          'Weibo' => 'Chinese microblogging site produced by Sina.',
          'Songza' => 'Web radio and music streaming service.',
          'VKontakte' => 'Russian social networking service.',
          'Badoo' => 'Social networking service.',
          'FileServe' => 'File hosting and sharing service.',
          'MyDownloader' => 'Service for downloading files from numerous file hosting sites such as Rapidshare.',
          'TwitPic' => 'Site for posting and sharing photos and videos on twitter.',
          'Scribd' => 'Web based document posting and sharing service.',
          'FilmOn' => 'Subscription based video on demand and TV streaming service.',
          'Jango' => 'Internet radio and social networking service.',
          'Mibbit' => 'Web based chat client that supports IRC and Twitter.',
          'Evony' => 'Browser-based online multiplayer game.',
          'Megashare' => 'File hosting and sharing service. Distinct from Megashares.',
          'SoundCloud' => 'Music platform for artists to upload and promote their music.',
          'Youku' => 'Chinese video hosting and sharing service.',
          'Kaixin001' => 'Chinese based social networking service.',
          'VTunnel' => 'Web based proxy service.',
          'MyHeritage' => 'Family oriented social networking service.',
          'DivShare' => 'File hosting and sharing service.',
          'Livemocha' => 'Language learning community and platform offering free and paid language courses.',
          'Webhard' => 'Online storage service available in Korean and English.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'Tagged' => 'Social networking site based in California.',
          'Daum' => 'Popular South Korean web portal.',
          'Deezer' => 'Music streaming service based in Paris.',
          'Licorize' => 'Social bookmarking service.',
          'Douban' => 'Chinese social networking service.',
          'BigBlueButton' => 'Web conferencing system.',
          'Me2day' => 'South Korean based social networking service.',
          'hi5' => 'Social networking and social gaming platform.',
          'yfrog' => 'Site for posting and sharing photos and videos on twitter.',
          'Surrogafier' => 'Free proxy service.',
          'Gaia Online' => 'Anime themed social networking and forums website.',
          'The Hype Machine' => 'MP3 blog aggregator.',
          'Afreeca' => 'Video streaming service based in South Korea.',
          'Tuenti' => 'Invite only social networking website based in Spain.',
          'Skyrock' => 'Social networking site popular in France.',
          'Jamendo' => 'Website that allows for the streaming, downloading, and uploading of free music.',
          'dl.free.fr' => 'French based file hosting service.',
          'Neopets' => 'Virtual pet website.',
          'Movieclips' => 'Streaming video site for movie clips.',
          '4chan' => 'Website that hosts found images and discussions on them.',
          'Omegle' => 'Online chat service that pairs together strangers.',
          'Odnoklassniki' => 'Russian social networking service.',
          'Cyworld' => 'South Korean social networking service.',
          'ProxEasy' => 'Anonymous web based proxy service.',
          'MegaMeeting' => 'Web based conferencing platform.',
          'Crackle' => 'Digital network providing streaming video content.',
          'Phanfare' => 'Subscription based photo and video sharing service.',
          'xda-developers' => 'Large online community of smartphone and tablet enthusiasts and developers.',
          'NeoGAF' => 'Internet forum based around video games.',
          'Livestream' => 'Live streaming video platform.',
          'Chatroulette' => 'Service that pairs random strangers for video chat.',
          '51.com' => 'Chinese social networking site.',
          'Filemail' => 'File hosting and sharing service.',
          'Rhapsody' => 'Online streaming music service.',
          'Qriocity' => 'Streaming music and video on demand service from Sony.',
          'Justin.tv' => 'Live streaming video platform.',
          'DepositFiles' => 'International file hosting and sharing service.',
          'Issuu' => 'Web based document posting and sharing service.',
          '56.com' => 'Large Chinese video sharing site.',
          'Balatarin' => 'Social bookmarking and community website aimed at an Iranian audience.',
          'MOG' => 'Paid subscription online music service with streaming capability.',
          'Insight' => 'Computer and electronic products retailer.',
          'Webshots' => 'Service for uploading and sharing photos and videos.',
          'FORA.tv' => 'Website hosting videos of live events, lectures, and debates.',
          'iHeartRadio' => 'Website that provides streaming access to local and digital-only radio stations.',
          'Dangdang' => 'Chinese general E-commerce company.',
          'RuTube' => 'Russian online video sharing service.',
          'BigUpload' => 'File hosting and sharing service.',
          'PC Connection' => 'Computer and electronic products retailer.',
          'CloudMe' => 'Web desktop service.',
          '7digital' => 'Digital music and video delivery company.',
          'Babelgum' => 'Internet TV service.',
          'FileDropper' => 'File hosting and sharing service.',
          'TwitchTV' => 'Justin.tv gaming specific livestreaming platform.',
          'Jubii' => 'Web portal providing search engine, e-mail, and file sharing services.',
          'Slacker' => 'Internet radio service.',
          'WooMe' => 'Online service in which users meet and interact through video chat.',
          'RuneScape' => 'Browser based fantasy role-playing game.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_devo",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--ProxEasy
	{ 0, 0, 0, 333, 46, "proxeasy.com", "/", "http:", "", 1001 },
	--Qriocity
	{ 0, 0, 0, 334, 13, "qriocity.com", "/", "http:", "", 1002 },
	--RuneScape
	{ 0, 0, 0, 335, 20, "runescape.com", "/", "http:", "", 1003 },
	--Scribd
	{ 0, 0, 0, 337, 9, "scribd.com", "/", "http:", "", 1005 },
	--Songza
	{ 0, 0, 0, 338, 13, "songza.com", "/", "http:", "", 1006 },
	--SoundCloud
	{ 0, 0, 0, 339, 9, "soundcloud.com", "/", "http:", "", 1007 },
	--Surrogafier
	{ 0, 0, 0, 343, 46, "surrogafier.info", "/", "http:", "", 1011 },
	--Tinychat
	{ 0, 0, 0, 345, 10, "tinychat.com", "/", "http:", "", 1013 },
	--Tudou
	{ 0, 0, 0, 346, 13, "tudou.com", "/", "http:", "", 1014 },
	--TransferBigFiles.com
	{ 0, 0, 0, 347, 9, "transferbigfiles.com", "/", "http:", "", 1015 },
	--Tuenti
	{ 0, 0, 0, 348, 5, "tuenti.com", "/", "http:", "", 1016 },
	--VKontakte
	{ 0, 0, 0, 350, 5, "vkontakte.ru", "/", "http:", "", 1018 },
	--VTunnel
	{ 0, 0, 0, 351, 46, "vtunnel.com", "/", "http:", "", 1019 },
	--Webhard
	{ 0, 0, 0, 352, 9, "webhard.net", "/", "http:", "", 1020 },
	--Webshots
	{ 0, 0, 0, 353, 9, "webshots.com", "/", "http:", "", 1021 },
	--Weibo
	{ 0, 0, 0, 354, 5, "weibo.com", "/", "http:", "", 1022 },
	--WooMe
	{ 0, 0, 0, 357, 5, "woome.com", "/", "http:", "", 1025 },
	--BigUpload
	{ 0, 0, 0, 359, 9, "bigupload.com", "/", "http:", "", 1027 },
	--Clarizen
	{ 0, 0, 0, 360, 43, "clarizen.com", "/", "http:", "", 1028 },
	--56.com
	{ 0, 0, 0, 363, 13, "56.com", "/", "http:", "", 1031 },
	--51.com
	{ 0, 0, 0, 364, 5, "51.com", "/", "http:", "", 1032 },
	--Youku
	{ 0, 0, 0, 365, 13, "youku.com", "/", "http:", "", 1033 },
	--Crackle
	{ 0, 0, 0, 366, 13, "crackle.com", "/", "http:", "", 1034 },
	--RuTube
	{ 0, 0, 0, 367, 13, "rutube.ru", "/", "http:", "", 1035 },
	--Afreeca
	{ 0, 0, 0, 369, 13, "afreeca.com", "/", "http:", "", 1037 },
	--Babelgum
	{ 0, 0, 0, 370, 13, "babelgum.com", "/", "http:", "", 1038 },
	--MOG
	{ 0, 0, 0, 373, 13, "mog.com", "/", "http:", "", 1041 },
	--Phanfare
	{ 0, 0, 0, 378, 9, "phanfare.com", "/", "http:", "", 1046 },
	--FilmOn
	{ 0, 0, 0, 380, 13, "filmon.com", "/", "http:", "", 1048 },
	--Mibbit
	{ 0, 0, 0, 381, 10, "mibbit.com", "/", "http:", "", 1049 },
	--BigBlueButton
	{ 0, 0, 0, 382, 21, "bigbluebutton.org", "/", "http:", "", 1050 },
	--TwitchTV
	{ 0, 0, 0, 383, 13, "twitch.tv", "/", "http:", "", 1051 },
	--MegaMeeting
	{ 0, 0, 0, 384, 21, "megameeting.co", "/", "http:", "", 1052 },
	--Badoo
	{ 0, 0, 0, 385, 5, "badoo.com", "/", "http:", "", 1053 },
	--DepositFiles
	{ 0, 0, 0, 386, 9, "depositfiles.com", "/", "http:", "", 1054 },
	--CloudMe
	{ 0, 0, 0, 387, 22, "cloudme.com", "/", "http:", "", 1055 },
	--Skyrock
	{ 0, 0, 0, 389, 5, "skyrock.com", "/", "http:", "", 1057 },
	--Jubii
	{ 0, 0, 0, 392, 22, "jubii.dk", "/", "http:", "", 1060 },
	--TwitPic
	{ 0, 0, 0, 395, 9, "twimg.com", "/", "http:", "", 1063 },
	--yfrog
	{ 0, 0, 0, 396, 9, "yfrog.com", "/", "http:", "", 1064 },
	--Tagged
	{ 0, 0, 0, 397, 5, "tagged.com", "/", "http:", "", 1065 },
	--hi5
	{ 0, 0, 0, 398, 5, "hi5.com", "/", "http:", "", 1066 },
	--Livemocha
	{ 0, 0, 0, 399, 12, "livemocha.com", "/", "http:", "", 1067 },
	--Slacker
	{ 0, 0, 0, 400, 13, "slacker.com", "/", "http:", "", 1068 },
	--Douban
	{ 0, 0, 0, 401, 5, "douban.com", "/", "http:", "", 1069 },
	--Odnoklassniki
	{ 0, 0, 0, 402, 5, "odnoklassniki.ru", "/", "http:", "", 1070 },
	--Gaia Online
	{ 0, 0, 0, 403, 5, "gaiaonline.com", "/", "http:", "", 1071 },
	--MyHeritage
	{ 0, 0, 0, 404, 5, "myheritage.", "/", "http:", "", 1072 },
	--AutoZone
	{ 0, 0, 0, 405, 36, "autozone.com", "/", "http:", "", 1073 },
	--Dangdang
	{ 0, 0, 0, 406, 45, "dangdang.com", "/", "http:", "", 1074 },
	--Insight
	{ 0, 0, 0, 407, 27, "pcmall.com", "/", "http:", "", 1075 },
	--Tesco.com
	{ 0, 0, 0, 409, 45, "tesco.com", "/", "http:", "", 1077 },
	--xda-developers
	{ 0, 0, 0, 410, 23, "xda-developers.com", "/", "http:", "", 1078 },
	--4chan
	{ 0, 0, 0, 411, 23, "4chan.org", "/", "http:", "", 1079 },
	--NeoGAF
	{ 0, 0, 0, 412, 23, "neogaf.com", "/", "http:", "", 1080 },
	--Rhapsody
	{ 0, 0, 0, 413, 13, "rhapsody.com", "/", "http:", "", 1081 },
	--Balatarin
	{ 0, 0, 0, 414, 14, "balatarin.com", "/", "http:", "", 1082 },
	--Movieclips
	{ 0, 0, 0, 416, 13, "movieclips.com", "/", "http:", "", 1084 },
	--PC Connection
	{ 0, 0, 0, 408, 27, "pcconnection.com", "/", "http:", "", 1109 },
	--7digital
	{ 0, 0, 0, 291, 15, "7digital.com", "/", "http:", "", 959 },
	--Chatroulette
	{ 0, 0, 0, 294, 10, "chatroulette.com", "/", "http:", "", 962 },
	--Cyworld
	{ 0, 0, 0, 295, 5, "cyworld.co", "/", "http:", "", 963 },
	--Daum
	{ 0, 0, 0, 296, 22, "daum.net", "/", "http:", "", 964 },
	--Deezer
	{ 0, 0, 0, 297, 13, "deezer.com", "/", "http:", "", 965 },
	--DivShare
	{ 0, 0, 0, 298, 9, "divshare.com", "/", "http:", "", 966 },
	--dl.free.fr
	{ 0, 0, 0, 299, 9, "dl.free.fr", "/", "http:", "", 967 },
	--Evony
	{ 0, 0, 0, 302, 20, "evony.com", "/", "http:", "", 970 },
	--FileDropper
	{ 0, 0, 0, 303, 9, "filedropper.com", "/", "http:", "", 971 },
	--Filemail
	{ 0, 0, 0, 304, 9, "filemail.com", "/", "http:", "", 972 },
	--FileServe
	{ 0, 0, 0, 305, 9, "fileserve.com", "/", "http:", "", 973 },
	--Licorize
	{ 0, 0, 0, 306, 14, "licorize.com", "/", "http:", "", 974 },
	--folkd
	{ 0, 0, 0, 307, 14, "folkd.com", "/", "http:", "", 975 },
	--FORA.tv
	{ 0, 0, 0, 308, 1, "fora.tv", "/", "http:", "", 976 },
	--GMX Mail
	{ 0, 0, 0, 309, 4, "gmx.at", "/", "http:", "", 977 },
	--CiteULike
	{ 0, 0, 0, 311, 14, "citeulike.org", "/", "http:", "", 979 },
	--Habbo
	{ 0, 0, 0, 312, 5, "habbo.co", "/", "http:", "", 980 },
	--Hushmail
	{ 0, 0, 0, 313, 4, "hushmail.com", "/", "http:", "", 981 },
	--The Hype Machine
	{ 0, 0, 0, 314, 13, "hypem.com", "/", "http:", "", 982 },
	--iHeartRadio
	{ 0, 0, 0, 316, 13, "iheartradio.com", "/", "http:", "", 984 },
	--Issuu
	{ 0, 0, 0, 317, 9, "issuu.co", "/", "http:", "", 985 },
	--Jamendo
	{ 0, 0, 0, 318, 13, "jamendo.com", "/", "http:", "", 986 },
	--Jango
	{ 0, 0, 0, 319, 13, "jango.com", "/", "http:", "", 987 },
	--Justin.tv
	{ 0, 0, 0, 320, 13, "justin.tv", "/", "http:", "", 988 },
	--Kaixin001
	{ 0, 0, 0, 321, 5, "kaixin001.com", "/", "http:", "", 989 },
	--Livestream
	{ 0, 0, 0, 323, 13, "livestream.com", "/", "http:", "", 991 },
	--Me2day
	{ 0, 0, 0, 324, 5, "me2day.net", "/", "http:", "", 992 },
	--Megashare
	{ 0, 0, 0, 325, 9, "megashare.com", "/", "http:", "", 993 },
	--MyDownloader
	{ 0, 0, 0, 327, 9, "mydownloader.net", "/", "http:", "", 995 },
	--Neopets
	{ 0, 0, 0, 328, 20, "neopets.com", "/", "http:", "", 996 },
	--Omegle
	{ 0, 0, 0, 329, 10, "omegle.com", "/", "http:", "", 997 },
	--Mister Wong
	{ 0, 0, 0, 331, 14, "mister-wong.com", "/", "http:", "", 999 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    gDetector:addHttpPattern(2, 5, 0, 414, 19, 0, 0, 'iHeartRadio/', 984)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end
    return gDetector
end

function DetectorClean()
end
