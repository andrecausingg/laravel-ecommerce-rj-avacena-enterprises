<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class CounterLimiterMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $validator = Validator::make($request->all(), [
            'fingerprint' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(
                [
                    'message' => $validator->errors(),
                ],
                Response::HTTP_BAD_REQUEST
            );
        }

        $cacheKey = 'resend-code-' . $request->input('fingerprint');
        $maxAttempts = 5; // Maximum number of allowed attempts
        $blockPeriod = 7200; // Block period in seconds (2 hours)

        // Check if there's already an attempt count
        if (Cache::has($cacheKey)) {
            $cacheData = Cache::get($cacheKey);
            $attempts = $cacheData['attempts'];
            $firstAttemptTime = $cacheData['first_attempt_time'];

            // Check if the block period has passed
            if (now()->timestamp - $firstAttemptTime >= $blockPeriod) {
                // Reset attempts and time after block period
                $attempts = 0;
                $firstAttemptTime = now()->timestamp;
            }

            // Increment attempts and check against max attempts
            if ($attempts >= $maxAttempts) {
                return response()->json(
                    [
                        'message' => 'You have reached the maximum number of attempts. Please try again later.',
                    ],
                    Response::HTTP_TOO_MANY_REQUESTS
                );
            } else {
                $attempts++;
                Cache::put($cacheKey, ['attempts' => $attempts, 'first_attempt_time' => $firstAttemptTime], $blockPeriod);
            }
        } else {
            // Set initial attempts and first attempt time
            Cache::put($cacheKey, ['attempts' => 1, 'first_attempt_time' => now()->timestamp], $blockPeriod);
        }

        return $next($request);
    }
}
