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
detection_name: Payload Group "345"
version: 1
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Appier' => 'Appier is a technology company which aims to provide artificial intelligence (AI) platforms.',
          'Tidal' => 'Tidal is a subscription-based music, podcast and video streaming service.',
          'Stripe' => 'Stripe provides payment processing platforms.',
          'Firefly Education' => 'Australian site that provides educational resources.',
          'Taboola' => 'Native advertising platform.',
          'Discord' => 'VoIP, instant messaging and digital distribution platform designed for creating communities.',
          'Tappx' => 'Tappx is an open app developers community for monetization and cross-promotion.',
          'Mac App Store' => 'Online store for Mac OSX products. Different than Apple App Store, which is for iOS products.',
          'Honey' => 'Digital tool to find the best savings, perks, and all around value, coupons and discounts.',
          'Font Awesome' => 'Website for vector icons and social logos for websites.',
          'Grammarly' => 'Digital writing tool using artificial intelligence and natural language processing (auto corecting tool).',
          'Tokopedia' => 'Indonesian online marketplace.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_345",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Tokopedia
    { 0, 0, 0, 1983, 1, "tokopedia.net", "/", "http:", "", 4299},
    -- Stripe
    { 0, 0, 0, 1985, 1, "stripecdn.com", "/", "http:", "", 4614},
    { 0, 0, 0, 1985, 1, "stripe.com", "/", "http:", "", 4614},
    { 0, 0, 0, 1985, 1, "stripe.network", "/", "http:", "", 4614},
    -- Taboola
    { 0, 0, 0, 1984, 1, "taboola.com", "/", "http:", "", 4293},
    -- Tidal
    { 0, 0, 0, 1986, 1, "tidal.com", "/", "http:", "", 4604},
    -- Tappx
    { 0, 0, 0, 1987, 1, "tappx.com", "/", "http:", "", 4606},
    -- Appier
    { 0, 0, 0, 1988, 1, "appier.com", "/", "http:", "", 4605},
    -- Honey
    { 0, 0, 0, 1989, 1, "joinhoney.com", "/", "http:", "", 4599},
    { 0, 0, 0, 1989, 1, "honey-images.com", "/", "http:", "", 4599},
    { 0, 0, 0, 1989, 1, "honey.io", "/", "http:", "", 4599},
    -- Grammarly
    { 0, 0, 0, 1990, 1, "grammarly.com", "/", "http:", "", 4598},
    { 0, 0, 0, 1990, 1, "grammarly.io", "/", "http:", "", 4598},
    -- Firefly Education
    { 0, 0, 0, 1991, 1, "fireflyeducation.com.au", "/", "http:", "", 4597},
    -- Font Awesome
    { 0, 0, 0, 1992, 1, "fontawesome.com", "/", "http:", "", 4596},
    -- Mac App Store
    { 0, 0, 0, 1993, 1, "osxapps.itunes.apple.com", "/", "http:", "", 1680},
    -- Discord
    { 0, 0, 0, 1994, 1, "discord.com", "/", "http:", "", 4654},
    { 0, 0, 0, 1994, 1, "discord.gg", "/", "http:", "", 4654},
    { 0, 0, 0, 1994, 1, "discord.media", "/", "http:", "", 4654},
    { 0, 0, 0, 1994, 1, "discordapp.com", "/", "http:", "", 4654},
    { 0, 0, 0, 1994, 1, "discordapp.net", "/", "http:", "", 4654},
    { 0, 0, 0, 1994, 1, "discordstatus.com", "/", "http:", "", 4654},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end