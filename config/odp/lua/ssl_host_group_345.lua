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
detection_name: SSL Group "345"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Appier' => 'Appier is a technology company which aims to provide artificial intelligence (AI) platforms.',
          'Tidal' => 'Tidal is a subscription-based music, podcast and video streaming service.',
          'Tappx' => 'Tappx is an open app developers community for monetization and cross-promotion.',
          'Stripe' => 'Stripe provides payment processing platforms.',
          'Honey' => 'Digital tool to find the best savings, perks, and all around value, coupons and discounts.',
          'Firefly Education' => 'Australian site that provides educational resources.',
          'Font Awesome' => 'Website for vector icons and social logos for websites.',
          'Taboola' => 'Native advertising platform.',
          'Mac App Store' => 'Online store for Mac OSX products. Different than Apple App Store, which is for iOS products.',
          'Tokopedia' => 'Indonesian online marketplace.',
          'Grammarly' => 'Digital writing tool using artificial intelligence and natural language processing (auto corecting tool).',
          'Discord' => 'VoIP, instant messaging and digital distribution platform designed for creating communities.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_345",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Tokopedia
    {0, 4299, 'tokopedia.com', },    
    -- Taboola
    {0, 4293, 'taboola.com', },
    -- Stripe
    {0, 4614, 'stripe.com', },
    -- Tidal
    {0, 4604, 'tidal.com', },
    -- Tappx
    {0, 4606, 'tappx.com', },
    -- Appier
    {0, 4605, 'appier.com', },
    -- Honey
    {0, 4599, 'joinhoney.com', },
    -- Grammarly
    {0, 4598, 'grammarly.com', },
    -- Firefly Education
    {0, 4597, 'fireflyeducation.com.au', },
    -- Font Awesome
    {0, 4596, 'fontawesome.com', },
    -- Mac App Store
    {0, 1680, 'osxapps.itunes.apple.com', },
    -- Discord
    {0, 4654, 'discord.com', },
    {0, 4654, 'discord.gg', },
    {0, 4654, 'discord.media', },
    {0, 4654, 'discordapp.com', },
    {0, 4654, 'discordapp.net', },
    {0, 4654, 'discordstatus.com', },
}

gSSLCnamePatternList = {
    -- Tokopedia
    {0, 4299, 'tokopedia.com', },
    -- Taboola
    {0, 4293, 'taboola.com', },
    -- Stripe
    {0, 4614, 'stripe.com', },
    -- Tidal
    {0, 4604, 'tidal.com', },
    -- Tappx
    {0, 4606, 'tappx.com', },
    -- Appier
    {0, 4605, 'appier.com', },
    -- Honey
    {0, 4599, 'joinhoney.com', },
    -- Grammarly
    {0, 4598, 'grammarly.com', },
    -- Firefly Education
    {0, 4597, 'fireflyeducation.com.au', },
    -- Font Awesome
    {0, 4596, 'fontawesome.com', },
    -- Mac App Store
    {0, 1680, 'osxapps.itunes.apple.com', },
    -- Discord
    {0, 4654, 'discord.media', },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end