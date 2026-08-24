// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

#include <metal_stdlib>
using namespace metal;

struct GlobeVertexOut {
    float4 position [[position]];
    float2 uv;
};

struct GlobeUniforms {
    float4 right;
    float4 up;
    float4 forward;
    float4 sun;
    float4 viewport;
};

vertex GlobeVertexOut globeVertex(uint id [[vertex_id]]) {
    constexpr float2 positions[3] = { float2(-1, -1), float2(3, -1), float2(-1, 3) };
    GlobeVertexOut out;
    out.position = float4(positions[id], 0, 1);
    out.uv = positions[id] * 0.5 + 0.5;
    return out;
}

fragment float4 globeFragment(GlobeVertexOut in [[stage_in]],
                              constant GlobeUniforms& uniforms [[buffer(0)]],
                              texture2d<float> dayEarth [[texture(0)]],
                              texture2d<float> nightLights [[texture(1)]]) {
    const float aspect = uniforms.viewport.x / max(uniforms.viewport.y, 1.0f);
    const float radius = 0.45f;
    const float2 plane = float2((in.uv.x - 0.5f) * aspect, in.uv.y - 0.5f);
    const float distance = length(plane);
    if (distance > radius) {
        const float vignette = smoothstep(radius, radius + 0.22f, distance);
        return float4(mix(float3(0.055f, 0.070f, 0.105f), float3(0.025f, 0.030f, 0.050f), vignette), 1);
    }

    const float2 disk = plane / radius;
    const float depth = sqrt(max(0.0f, 1.0f - dot(disk, disk)));
    // SwiftUI's Canvas has a top-left origin. Match that projection exactly so
    // coastlines, routes and native pin views remain pinned to Metal's globe.
    const float3 world = normalize(uniforms.right.xyz * disk.x
                                   + uniforms.up.xyz * disk.y
                                   + uniforms.forward.xyz * depth);
    const float latitude = asin(clamp(world.y, -1.0f, 1.0f));
    const float longitude = atan2(world.z, world.x);
    constexpr sampler landSampler(coord::normalized, address::repeat, filter::linear);
    // GreatCircle, Canvas and NASA's equirectangular assets all use longitude
    // increasing from west to east. Keep this direct mapping so the imagery
    // stays registered with the border overlay, route and server pins.
    const float2 equirectangular = float2((longitude + M_PI_F) / (2.0f * M_PI_F),
                                          0.5f - latitude / M_PI_F);
    const float3 dayTexture = dayEarth.sample(landSampler, equirectangular).rgb;
    const float3 cityLights = nightLights.sample(landSampler, equirectangular).rgb;
    const float parallel = abs(sin(latitude * 9.0f));
    const float meridian = abs(sin(longitude * 12.0f));
    // The graticule is orientation support, not map content. Keep it barely
    // perceptible so the land, active route and server pins lead the eye.
    const float line = smoothstep(0.014f, 0.0f, min(parallel, meridian));
    const float limb = smoothstep(radius, radius - 0.028f, distance);
    // A generous 12° twilight band avoids a hard moving edge. The terminator
    // follows the local UTC solar vector; only the persistent VIIRS light map
    // is exposed on the actual night side.
    const float sunAltitude = dot(world, normalize(uniforms.sun.xyz));
    const float daylight = smoothstep(-0.12f, 0.10f, sunAltitude);
    const float3 daySurface = dayTexture * (0.58f + 0.42f * max(sunAltitude, 0.0f));
    const float3 nightBase = dayTexture * (0.018f + 0.052f * max(sunAltitude, 0.0f));
    const float3 nightSurface = nightBase + cityLights * 1.35f;
    float3 surface = mix(nightSurface, daySurface, daylight);
    surface += line * mix(float3(0.080f, 0.110f, 0.145f), float3(0.055f, 0.090f, 0.120f), daylight);
    surface += (1.0f - limb) * float3(0.12f, 0.28f, 0.43f);
    return float4(surface, 1);
}
