<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Crypt;
use Symfony\Component\HttpFoundation\Response;

class LogController extends Controller
{
    public function index(Request $request)
    {
        // Get the fields that need to be decrypted from the configuration
        $fields = config('encrypted-fields');

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }
        // Retrieve logs
        $logs = LogsModel::get();

        $decryptedDatas = [];

        foreach ($logs as $log) {
            $decryptedData = [];
        
            // Check if the log has details and if it's a valid JSON
            if (isset($log->details)) {
                $details = json_decode($log->details, true);
        
                // Iterate through each field that needs decryption
                foreach ($fields as $field) {
                    // Check if the field exists in the details and is a string
                    if (isset($details['fields'][$field]) && is_string($details['fields'][$field])) {
                        // Decrypt the field and add it to the decrypted data array
                        $decryptedData[$field] = Crypt::decrypt($details['fields'][$field]);
                    } else {
                        // Field not found or not a string, store the field itself
                        $decryptedData[$field] = $field;
                    }
                }
            }
            
            // Add the decrypted log data to the result array
            $decryptedDatas[] = $decryptedData;
        }
        


        return response()->json([
            'message' => 'Successfully Retrieve Data',
            'result' => $decryptedDatas,
        ], Response::HTTP_OK);

        // return response()->json([
        //     'message' => 'Successfully Retrieve Data',
        //     'result' => $logs,
        // ], Response::HTTP_OK);
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
}
