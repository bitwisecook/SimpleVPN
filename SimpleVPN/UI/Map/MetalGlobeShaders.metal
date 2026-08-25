// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

#include <metal_stdlib>
using namespace metal;

struct GlobeSample {
    float distance;
    float radius;
    float3 world;
    float2 textureCoordinate;
};

static GlobeSample globeSample(float2 position,
                               float4 bounds,
                               float3 right,
                               float3 up,
                               float3 forward) {
    const float2 size = max(bounds.zw, float2(1.0f));
    const float2 uv = (position - bounds.xy) / size;
    const float aspect = size.x / size.y;
    const float radius = 0.45f;
    const float2 plane = float2((uv.x - 0.5f) * aspect, uv.y - 0.5f);
    const float distance = length(plane);
    const float2 disk = plane / radius;
    const float depth = sqrt(max(0.0f, 1.0f - dot(disk, disk)));

    // SwiftUI Canvas and shape shaders share a top-left origin, so positive
    // screen Y points down. The overlay projection subtracts world-up from
    // screen Y; invert it here as well so imagery, coastlines, routes and pins
    // all use the same north-up camera basis.
    const float3 world = normalize(right * disk.x - up * disk.y + forward * depth);
    const float latitude = asin(clamp(world.y, -1.0f, 1.0f));
    const float longitude = atan2(world.z, world.x);
    const float2 equirectangular = float2((longitude + M_PI_F) / (2.0f * M_PI_F),
                                          0.5f - latitude / M_PI_F);
    return { distance, radius, world, equirectangular };
}

/// Opaque base pass: Blue Marble, live sun/terminator, graticule, and an
/// atmosphere that glows both through the limb and just beyond it.
[[ stitchable ]] half4 globeDay(float2 position,
                                float4 bounds,
                                float3 right,
                                float3 up,
                                float3 forward,
                                float3 sun,
                                texture2d<half> dayEarth) {
    const GlobeSample globe = globeSample(position, bounds, right, up, forward);
    const float vignette = smoothstep(globe.radius, globe.radius + 0.22f, globe.distance);
    float3 background = mix(float3(0.055f, 0.070f, 0.105f),
                            float3(0.025f, 0.030f, 0.050f), vignette);

    if (globe.distance > globe.radius) {
        const float outerAtmosphere = 1.0f - smoothstep(globe.radius,
                                                        globe.radius + 0.032f,
                                                        globe.distance);
        background += outerAtmosphere * float3(0.055f, 0.15f, 0.30f);
        return half4(half3(background), 1.0h);
    }

    constexpr sampler earthSampler(coord::normalized, address::repeat, filter::linear);
    const float3 dayTexture = float3(dayEarth.sample(earthSampler, globe.textureCoordinate).rgb);
    const float latitude = asin(clamp(globe.world.y, -1.0f, 1.0f));
    const float longitude = atan2(globe.world.z, globe.world.x);
    const float parallel = abs(sin(latitude * 9.0f));
    const float meridian = abs(sin(longitude * 12.0f));
    const float line = 1.0f - smoothstep(0.0f, 0.014f, min(parallel, meridian));
    const float interior = 1.0f - smoothstep(globe.radius - 0.028f,
                                             globe.radius,
                                             globe.distance);

    // A broad twilight band keeps the terminator natural while the dark base
    // retains enough Blue Marble detail for the city-light pass above it.
    const float sunAltitude = dot(globe.world, normalize(sun));
    const float daylight = smoothstep(-0.12f, 0.10f, sunAltitude);
    const float3 daySurface = dayTexture * (0.58f + 0.42f * max(sunAltitude, 0.0f));
    const float3 nightSurface = dayTexture * (0.018f + 0.052f * max(sunAltitude, 0.0f));
    float3 surface = mix(nightSurface, daySurface, daylight);
    surface += line * mix(float3(0.080f, 0.110f, 0.145f),
                          float3(0.055f, 0.090f, 0.120f), daylight);
    surface += (1.0f - interior) * float3(0.12f, 0.28f, 0.43f);
    return half4(half3(surface), 1.0h);
}

/// Transparent additive-looking pass. SwiftUI permits one image argument per
/// Shader, so Black Marble is sampled separately and only its luminous pixels
/// are composited over the opaque day/atmosphere pass.
[[ stitchable ]] half4 globeNightLights(float2 position,
                                        float4 bounds,
                                        float3 right,
                                        float3 up,
                                        float3 forward,
                                        float3 sun,
                                        texture2d<half> nightEarth) {
    const GlobeSample globe = globeSample(position, bounds, right, up, forward);
    if (globe.distance > globe.radius) {
        return half4(0.0h);
    }

    constexpr sampler earthSampler(coord::normalized, address::repeat, filter::linear);
    const float3 lights = float3(nightEarth.sample(earthSampler, globe.textureCoordinate).rgb);
    const float luminance = max(lights.r, max(lights.g, lights.b));
    const float sunAltitude = dot(globe.world, normalize(sun));
    const float night = 1.0f - smoothstep(-0.12f, 0.10f, sunAltitude);
    const float interior = 1.0f - smoothstep(globe.radius - 0.018f,
                                             globe.radius,
                                             globe.distance);
    const float alpha = saturate(smoothstep(0.075f, 0.62f, luminance) * night * interior);
    const float3 colour = lights / max(luminance, 0.001f);
    return half4(half3(colour * alpha), half(alpha));
}
