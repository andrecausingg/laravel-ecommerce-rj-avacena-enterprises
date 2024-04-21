<?php

namespace App\Http\Controllers\Helper;

use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpFoundation\Response;

class Helper
{
    public function unsetColumn($unsets, $fillableAttr)
    {
        foreach ($unsets as $unset) {
            // Find the key associated with the field and unset it
            $key = array_search($unset, $fillableAttr);
            if ($key !== false) {
                unset($fillableAttr[$key]);
            }
        }

        return $fillableAttr;
    }

    public function authorizeUser($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return response()->json(['error' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();
            if (!$bearerToken || $user->session_token !== $bearerToken || $user->session_expire_at < Carbon::now()) {
                return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function upperCaseSpecific($validatedData, $colUpperCase)
    {
        foreach ($validatedData as $key => $value) {
            // Check if the field should be transformed to uppercase
            if (in_array($key, $colUpperCase)) {
                $validatedData[$key] = strtoupper($value);
            }
        }

        return $validatedData;
    }
}
