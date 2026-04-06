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
detection_name: Payload Group "INXS"
version: 41
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'NBC News' => 'NBCUniversal\'s news website.',
          'Google Play Books' => 'Google ebook reader.',
          'Mint.com' => 'Web-based personal finance tool.',
          'Bubble Saga' => 'Facebook bubble bursting game.',
          'Slotomania' => 'Facebook slots game.',
          'Dictionary.com' => 'Online free dictionary.',
          'Google Finance' => 'Stock quotes and news.',
          'Apple Trailers' => 'Portal for quicktime motion picture trailers.',
          'iAstrology' => 'Facebook astrology app.',
          'Instagram' => 'Mobile phone photo sharing.',
          'BranchOut' => 'Facebook professional networking.',
          'Google Play' => 'Google Play Store for Android applications.',
          'CNN.com' => 'Turner Broadcasting System\'s news website.',
          'Flock' => 'A web browser.',
          'Daily Horoscope' => 'A Facebook astrology app.',
          'Bejeweled Blitz' => 'Facebook version of Bejeweled 2.',
          'Bing Maps' => 'Microsoft online mapping and directions service.',
          'Social Empires' => 'Strategy game for Facebook.',
          'DoubleDownCasino' => 'Facebook casino games.',
          'Bild.de' => 'Online edition of German tabloid.',
          'IMDB' => 'Movie information, reviews and previews.',
          'Google Play Music' => 'Google cloud music storage and streaming.',
          'Elinks' => 'A web browser.',
          'Bejeweled Chrome Extension' => 'Bejeweled for the Chrome browser.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_inxs",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- cnn.com
    { 0, 0, 0, 450, 33, "cnn.com", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cdn.turner.com", "/cnn", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnn-f.akamaihd.net", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnnios-f.akamaihd.net", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnnchile.com", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnnmexico.com", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnn.co.jp", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnnturk.com", "/", "http:", "", 1190 },
    { 0, 0, 0, 450, 33, "cnn.sdk.beemray.com", "/", "http:", "", 1190 },
    -- IMDB
    { 0, 0, 0, 451, 33, "imdb.com", "/", "http:", "", 1191 },
    { 0, 0, 0, 451, 33, "media-imdb.com", "/", "http:", "", 1191 },
    -- NBC News
    { 0, 0, 0, 452, 33, "msnbc.com", "/", "http:", "", 1192 },
    { 0, 0, 0, 452, 33, "msnbc.msn.com", "/", "http:", "", 1192 },
    { 0, 0, 0, 452, 33, "nbcnews.com", "/", "http:", "", 1192 },
    -- Mint.com
    { 0, 0, 0, 453, 11, "mint.com", "/", "http:", "", 1193 },
    -- Apple Trailers
    { 0, 0, 0, 454, 13, "trailers.apple.com", "/", "http:", "", 1194 },
    -- Dictionary.com
    { 0, 0, 0, 455, 12, "dictionary.com", "/", "http:", "", 1195 },
    { 0, 0, 0, 455, 12, "dictionary.reference.com", "/", "http:", "", 1195},
    -- Bild.de
    { 0, 0, 0, 456, 33, "bild.de", "/", "http:", "", 1196 },
    -- Bing Maps
    { 0, 0, 0, 457, 37, "bing.com", "/maps", "http:", "", 1197 },
    { 0, 0, 0, 457, 37, "virtualearth.net", "/", "http:", "", 1197 },
    { 0, 0, 0, 457, 37, "maps.bing.com", "/", "http:", "", 1197 },
    { 0, 0, 0, 457, 37, "www.bing.com", "/maps", "http:", "", 1197 },
    -- Google Finance
    { 0, 0, 0, 458, 39, "google.com", "/finance", "http:", "", 1198 },
    -- Bejewled Chrome extension
    { 0, 0, 0, 459, 20, "bejeweled.popcap.com", "/html5", "http:", "", 1229 },
    { 0, 0, 0, 459, 20, "gats.popcap.com", "/bejeweled-html5", "http:", "", 1229 },
    -- Google Play
    { 0, 0, 0, 1874, 48, "play.google.com", "/", "http:", "", 2469 },
    -- Google Play Books
    { 0, 0, 0, 460, 7, "books.google.com", "/", "http:", "", 1230 },
    { 0, 0, 0, 460, 7, "play.google.com", "/books", "http:", "", 1230 },
    { 0, 0, 0, 460, 7, "play.google.com", "/googlebooks", "http:", "", 1230 },
    -- Google Play Music
    { 0, 0, 0, 461, 7, "googleusercontent.com", "/videoplayback", "http:", "", 1231 },
    { 0, 0, 0, 461, 7, "video.google.com", "/stream_", "http:", "", 1231 },
    { 0, 0, 0, 461, 7, "play.google.com", "/music", "http:", "", 1231 },
    { 0, 0, 0, 461, 7, "music.google.com", "/", "http:", "", 1231 },
    -- Google Readre
    --{ 0, 0, 0, 462, 3, "google.com", "/reader", "http:", "", 1232 },
    -- Instagram
    { 0, 0, 0, 463, 9, "instagram.com", "/", "http:", "", 1233 },
    { 0, 0, 0, 463, 9, "instagram.fsxr3-1.fna.fbcdn.net", "/", "http:", "", 1233 },
    -- DoubleDownCasino
    { 0, 0, 0, 464, 20, "doubledowncasino.com", "/", "http:", "", 1234 },
    -- 60photos
    --{ 0, 0, 0, 465, 5, "sixtyphotos.com", "/", "http:", "", 1235 },
    --{ 0, 0, 0, 465, 5, "60photos.com", "/", "http:", "", 1235 },
    -- iAstrology
    { 0, 0, 0, 468, 5, "horoscope.s3.amazonaws.com", "/", "http:", "", 1238 },
    -- Social Empires
    { 0, 0, 0, 469, 20, "socialpointgames.com", "/appsfb/socialempires", "http:", "", 1239 },
    -- Daily Horoscope
    { 0, 0, 0, 471, 5, "apps.facebook.com", "/tageshoroskopdd", "http:", "", 1241 },
    -- Car Town
    --{ 0, 0, 0, 472, 20, "cartown.com", "/", "http:", "", 1242 },
    -- Slotomania
    { 0, 0, 0, 473, 20, "playtika.com", "/", "http:", "", 1243 },
    { 0, 0, 0, 473, 20, "slotomania.com", "/", "http:", "", 1243 },
    -- Bubble Saga
    { 0, 0, 0, 474, 20, "bubblesaga.king.com", "/", "http:", "", 1244 },
    -- Fruit Ninja Frenzy
    -- { 0, 0, 0, 476, 20, "fruitninjafrenzygame.info", "/", "http:", "", 1246 },
    -- Monster World
    -- { 0, 0, 0, 477, 20, "cdn-mw.wooga.com", "/", "http:", "", 1247 },
    -- { 0, 0, 0, 477, 20, "monsters.wooga.com", "/", "http:", "", 1247 },
    -- { 0, 0, 0, 477, 20, "facebook.com", "/monsterworld", "http:", "", 1247 },
    -- { 0, 0, 0, 477, 20, "apps.facebook.com", "/monster-world", "http:", "", 1247 },
    -- { 0, 0, 0, 477, 20, "woo.ga", "/MonsterWorld", "http:", "", 1247 },
    -- 21 Questions
    --{ 0, 0, 0, 478, 20, "robosaint.com", "/", "http:", "", 1248 },
    ---- schoolFeed
    --{ 0, 0, 0, 479, 5, "schoolfeed.com", "/", "http:", "", 1249 },
    -- BranchOut
    { 0, 0, 0, 480, 5, "branchout.com", "/", "http:", "", 1250 },
    -- Bejewled Blitz
    { 0, 0, 0, 482, 20, "labs.popcap.com", "/facebook/bj2", "http:", "", 1252 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 199, 1, 0, 0, 'Flock', 3765, 1);
    gDetector:addHttpPattern(2, 5, 0, 198, 1, 0, 0, 'ELinks', 1719, 1);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

