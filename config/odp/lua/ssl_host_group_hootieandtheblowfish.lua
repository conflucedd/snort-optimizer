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
detection_name: SSL Group "hootieandtheblowfish"
version: 29
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'AOL Mail' => 'AOL\'s email client and webmail.',
          'EdgeCast' => 'Verizon Digital Media Services content delivery network.',
          'Bomgar' => 'Remote desktop control and file transfer software.',
          'Telegram' => 'Telegram is a messaging app with a focus on speed and security.',
          'Info.com' => 'Search engine.',
          'Zalmos' => 'Web proxy/anonymizer.',
          'Facebook video' => 'Viewing video posted on Facebook.',
          'GMX Mail' => 'German based webmail service.',
          'Torrentz' => 'BitTorrent metasearch engine.',
          'Integral Ad Science' => 'Advertisement site.',
          'Rsupport' => 'A remote management application for PC support.',
          'Facebook Photos' => 'Photos traffic from Facebook.',
          'Mail.Ru' => 'Runet\'s free e-mail service.',
          'Tumblr' => 'A combined social network and microblogging platform.',
          'Facebook Message' => 'A message sent on Facebook.',
          'Outlook' => 'Microsoft email service.',
          'Browsec' => 'A VPN app.',
          'Google Duo' => 'Google\'s instant messaging and video app.',
          'Mail.ru Attachment' => 'Attaching a file to an email on mail.ru.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_hootieandtheblowfish",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- Rsupport
    { 0, 4110, 'startsupport.com'},


    -- Zalmos
    { 0, 4106, 'zalmos.com' },
    -- Browsec
    { 0, 4094, 'browsec.com' },
    { 0, 4094, 'postls.com' },
    { 0, 4094, 'postlm.com' },
    -- Tumblr
    { 0, 475, 'tumblr.com' },
    -- Torrentz
    { 0, 1138, 'torrentz.com' },
    { 0, 1138, 'torrentz.eu' },
    { 0, 1138, 'torrentz2.eu' },
    -- Bomgar
    { 0, 4107, 'bomgar.com' },
    { 0, 4107, 'bomgar-bomgar12.netdna-ssl.com' },
    -- Integral Ad Science
    { 0, 2532, 'integralplatform.com' },
    { 0, 2532, 'integralads.com' },
    -- EdgeCast
    { 0, 4111, 'edgecast.com' },
    -- GMX Mail
    { 0, 977, 'gmx.net' },
    { 0, 977, 'gmx.at' },
    { 0, 977, 'gmx.ch' },
    { 0, 977, 'gmx.oewabox.at' },
    { 0, 977, 'ui-portal.de' },
    { 0, 977, 'gmx.com' },
    { 0, 977, 'gmx.co.uk' },
    { 0, 977, 'gmx.co' },
    -- Info.com
    { 0, 3876, 'info.com' },
    -- Telegram
    { 0, 4116, 'tdesktop.com' },
    { 0, 4116, 'telegram.org' },
    { 0, 4116, 'telegram.me' },
    { 0, 4116, 't.me' },
    -- AOL Mail
    { 0, 546, 'mail.aol.com' },
    { 0, 546, 'mail.aol.co.uk' },
    { 0, 546, 'mail.aol.de' },
    { 0, 546, 'mail.aol.in' },
    { 0, 546, 'mail.aol.ca' },
    { 0, 546, 'mail.aol.jp' },
    { 0, 546, 'mail.aol.fr' },
    { 0, 546, 'webmail-aoltoday.comet.aol.com' },
    -- Facebook Message
    { 0, 1286, '0-edge-chat.facebook.com' },
    { 0, 1286, '1-edge-chat.facebook.com' },
    { 0, 1286, '2-edge-chat.facebook.com' },
    { 0, 1286, '3-edge-chat.facebook.com' },
    { 0, 1286, '4-edge-chat.facebook.com' },
    { 0, 1286, '5-edge-chat.facebook.com' },
    { 0, 1286, '6-edge-chat.facebook.com' },
    --Facebook video
    { 0, 1287, 'video-iad3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-ord1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-lga3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-mrs1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-fra3-1.xx.fbcdn.net' },
    { 0, 1287, 'video.fash1-1.fna.fbcdn.net' },
    { 0, 1287, 'video-mia1-2.xx.fbcdn.net' },
    { 0, 1287, 'video-mia1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-sjc2-1.xx.fbcdn.net' },
    { 0, 1287, 'video-shv-01-mrs1.fbcdn.net' },
    { 0, 1287, 'video.ftpa1-1.fna.fbcdn.net' },
    { 0, 1287, 'video.fmex5-1.fna.fbcdn.net' },
    { 0, 1287, 'video.frir1-1.fna.fbcdn.net' },
    { 0, 1287, 'video-ort2-1.xx.fbcdn.net' },
    { 0, 1287, 'video-sin1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-mxp1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-hkg3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-tpe1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-ams3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-sea1-1.xx.fbcdn.net' },
    { 0, 1287, 'video-bru2-1.xx.fbcdn.net' },
    { 0, 1287, 'video-frt3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-lhr3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-lax3-1.xx.fbcdn.net' },
    { 0, 1287, 'video-arn2-1.xx.fbcdn.net' },
    { 0, 1287, 'video-ams2-1.xx.fbcdn.net' },
    { 0, 1287, 'fbcdn-video-a.akamaihd.net' },
    { 0, 1287, 'video-amt2-1.xx.fbcdn.net' },
    { 0, 1287, 'video-cai1-1.xx.fbcdn.net' },
    { 0, 1287, 'video.fkin2-1.fna.fbcdn.net' },
    --{ 0, 1287, 'scontent.fkin2-1.fna.fbcdn.net' },
    --{ 0, 1287, 'external.fkin2-1.fna.fbcdn.net' },
    --Google Duo
    { 0, 4127, 'duo.google.com' },
    --Outlook
    { 0, 776, 'diagnostics.outlook.com' },
    { 0, 776, 'login.windows-ppe.net' },
    --Mail.ru
    { 0, 1551, 'mail.ru' },
    -- Mail.ru Attachment
    { 0, 4091, 'attachmail.ru' },
    { 0, 4091, 'apf.mail.ru' },
    --Facebook Photos
    { 0, 2925, 'fbcdn-sphotos-a-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-b-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-c-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-d-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-e-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-f-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-g-a.akamaihd.net' },
    { 0, 2925, 'fbcdn-sphotos-h-a.akamaihd.net' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.AFAddApp then
        gDetector:AFAddApp(4116, 447, 4116)
    end

    return gDetector;
end

function DetectorClean()
end

