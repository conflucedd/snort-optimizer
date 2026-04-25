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
detection_name: Payload Group "hootieandtheblowfish"
version: 15
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Baidu Yun' => 'Baidu cloud storage and P2P file transfer.',
          'Browsec' => 'A VPN app.',
          'Telegram' => 'Telegram is a messaging app with a focus on speed and security.',
          'AOL Mail' => 'AOL\'s email client and webmail.',
          'Burnbook' => 'Anonymous messaging app.',
          'Oracle Business Intelligence' => 'Used by Oracle systems.',
          'Hello' => 'Hello is a social networking service.',
          'Ngrok' => 'Multiplatform tunnelling, reverse proxy software.',
          'Zalmos' => 'Web proxy/anonymizer.',
          'EdgeCast' => 'Verizon Digital Media Services content delivery network.',
          'AOL Video' => 'Videos on AOL.com.',
          'AOL Games' => 'Online games on AOL.com.',
          'Nico Nico Douga Video' => 'Nico Nico Douga video streaming.',
          'WebM Files' => 'Site for sharing videos in webm format.',
          'Bomgar' => 'Remote desktop control and file transfer software.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_hootieandtheblowfish",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Zalmos
    { 0, 0, 0, 1858, 46, "zalmos.com", "/", "http:", "", 4106},
    -- Browsec
    { 0, 0, 0, 1859, 46, "browsec.com", "/", "http:", "", 4094},
    { 0, 0, 0, 1859, 46, "postls.com", "/", "http:", "", 4094},
    { 0, 0, 0, 1859, 46, "postlm.com", "/", "http:", "", 4094},
    -- Bomgar
    { 0, 0, 0, 1860, 8, "bomgar.com", "/", "http:", "", 4107},
    -- Hello
    { 0, 0, 0, 1861, 5, "hello.com", "/", "http:", "", 4108},
    -- Oracle Business Intelligence
    { 0, 0, 0, 1862, 47, "holosbiprod.alltranstek.com", "/", "http:", "", 3692},
    -- WebM Files
    { 0, 0, 0, 1863, 9, "webmfiles.org", "/", "http:", "", 4109},
    -- Baidu Yun
    { 0, 0, 0, 1866, 9, "yun.baidu.com", "/", "http:", "", 4043},
    -- EdgeCast
    { 0, 0, 0, 1865, 19, "edgecast.com", "/", "http:", "", 4111},
    -- Burnbook
    { 0, 0, 0, 1867, 10, "p.typekit.net", "burnbookapp", "http:", "", 4046},
    { 0, 0, 0, 1867, 10, "burnbookapp.com", "/", "http:", "", 4046},
    -- Telegram
    { 0, 0, 0, 1868, 10, "tdesktop.com", "/", "http:", "", 4116},
    { 0, 0, 0, 1868, 10, "telegram.org", "/", "http:", "", 4116},
    { 0, 0, 0, 1868, 10, "telegram.me", "/", "http:", "", 4116},
    -- AOL Mail
    { 0, 0, 0, 13, 4, "mail.aol.com", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.co.uk", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.de", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.in", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.ca", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.jp", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.se", "/", "http:", "", 546},
    { 0, 0, 0, 13, 4, "mail.aol.fr", "/", "http:", "", 546},
    -- AOL Games
    { 0, 0, 0, 1870, 20, "games.aol.co.uk", "/", "http:", "", 4117},
    { 0, 0, 0, 1870, 20, "games.aol.de", "/", "http:", "", 4117},
    { 0, 0, 0, 1870, 20, "games.aol.com", "/", "http:", "", 4117},
    { 0, 0, 0, 1870, 20, "spiele.aol.de", "/", "http:", "", 4117},
    { 0, 0, 0, 1870, 20, "rs.aol.co.uk", "/games", "http:", "", 4117},
    { 0, 0, 0, 1870, 20, "rs.aol.de", "/games", "http:", "", 4117},
    { 0, 0, 0, 1870, 20, "aol.com", "/games", "http:", "", 4117},
    -- AOL Video
    { 0, 0, 0, 1871, 20, "aol.com", "/video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "aol.de", "/video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "aol.in", "/video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "aol.fr", "/video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "aol.co.uk", "/video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "rs.aol.co.uk", "/homepage.video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "rs.aol.fr", "/homepage.video", "http:", "", 4118},
    { 0, 0, 0, 1871, 20, "rs.aol.de", "/homepage.video", "http:", "", 4118},
    -- Nico Nico Douga Video
    { 0, 516, 13, 1873, 1, "live.nicovideo.jp", "/nicoliveplayer", "http:", "", 2611},
    -- Ngrok
    { 0, 0, 0, 1875, 46, "ngrok.io", "/", "http:", "", 4134},
    { 0, 0, 0, 1875, 46, "equinox.io", "/ngrok", "http:", "", 4134},
    { 0, 0, 0, 1875, 46, "s3.amazonaws.com", "/dns.ngrok.com/tunnel", "http:", "", 4134},
    { 0, 0, 0, 1875, 46, "ngrok.com", "/", "http:", "", 4134},
    { 0, 0, 0, 1875, 46, "korgn.su.lennut.com", "/", "http:", "", 4134},
}

gHostPortAppList = {
    -- type, AppId, IP Address, Port, Protocol
    { 1, 4116, "91.108.56.16",      80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.16",      443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.100",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.100",     443, DC.ipproto.tcp }, 
    { 1, 4116, "91.108.56.125",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.125",     443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.127",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.127",     443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.128",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.128",     443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.149",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.149",     443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.150",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.150",     443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.165",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.165",     443, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.190",     80, DC.ipproto.tcp },
    { 1, 4116, "91.108.56.190",     443, DC.ipproto.tcp },

    { 1, 4116, "104.239.13.181",    80, DC.ipproto.tcp },
    { 1, 4116, "104.239.13.181",    443, DC.ipproto.tcp },

    { 1, 4116, "149.154.164.250",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.164.250",    443, DC.ipproto.tcp },

    { 1, 4116, "149.154.165.120",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.165.120",    443, DC.ipproto.tcp },

    { 1, 4116, "149.154.166.120",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.166.120",    443, DC.ipproto.tcp },

    { 1, 4116, "149.154.167.24",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.24",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.25",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.25",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.40",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.40",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.42",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.42",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.50",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.50",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.51",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.51",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.80",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.80",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.90",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.90",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.91",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.91",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.92",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.92",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.99",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.99",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.117",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.117",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.118",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.118",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.192",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.167.192",    443, DC.ipproto.tcp },

    { 1, 4116, "149.154.171.5",     80, DC.ipproto.tcp },
    { 1, 4116, "149.154.171.5",     443, DC.ipproto.tcp },
    { 1, 4116, "149.154.171.146",   80, DC.ipproto.tcp },
    { 1, 4116, "149.154.171.146",   443, DC.ipproto.tcp },

    { 1, 4116, "149.154.174.9",     80, DC.ipproto.tcp },
    { 1, 4116, "149.154.174.9",     443, DC.ipproto.tcp },

    { 1, 4116, "149.154.175.10",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.10",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.50",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.50",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.51",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.51",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.52",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.52",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.53",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.53",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.54",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.54",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.55",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.55",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.56",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.56",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.57",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.57",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.58",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.58",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.59",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.59",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.117",    80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.117",    443, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.100",   80, DC.ipproto.tcp },
    { 1, 4116, "149.154.175.100",   443, DC.ipproto.tcp },

    { 1, 4116, "2001:b28:f23d:f001:0:0:0:e",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f001:0:0:0:e",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:67c:4e8:f002:0:0:0:e",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:67c:4e8:f002:0:0:0:e",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f003:0:0:0:e",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f003:0:0:0:e",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f001:0:0:0:a",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f001:0:0:0:a",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:67c:4e8:f002:0:0:0:a",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:67c:4e8:f002:0:0:0:a",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f003:0:0:0:a",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23d:f003:0:0:0:a",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:67c:4e8:f004:0:0:0:a",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:67c:4e8:f004:0:0:0:a",    443, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23f:f005:0:0:0:a",    80, DC.ipproto.tcp },
    { 1, 4116, "2001:b28:f23f:f005:0:0:0:a",    443, DC.ipproto.tcp },




}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Burnbook
    gDetector:addHttpPattern(2, 5, 0, 509, 16, 0, 0, 'Burnbook', 4046);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    if gDetector.addHostPortApp then
        for i,v in ipairs(gHostPortAppList) do
            gDetector:addHostPortApp(v[1],v[2],v[3],v[4],v[5]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
