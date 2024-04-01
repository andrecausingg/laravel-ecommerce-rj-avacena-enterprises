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
        $fields = config('encrypted-fields.encryptedFields');
        $decryptedLogs = [];
        $arrWithParentId = [];

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Retrieve logs
        $logs = LogsModel::get();

        // Iterate over each log
        foreach ($logs as $log) {
            // Decode the JSON string stored in the 'details' field
            $detailsJson = json_decode($log['details'], true);

            // Check if the 'fields' key exists in the details
            if (isset($detailsJson['fields'])) {
                // Check if the fields need to be decrypted
                $decryptedData = $this->isDecryptedData($detailsJson['fields'], $fields);

                // Store user_id and decrypted fields in a new array
                $arrWithParentId = [
                    'user_id' => $detailsJson['user_id'],
                    'fields' => $decryptedData
                ];
            }

            // Add the decrypted data to the result for this log
            $decryptedLogs[] = [
                'id' => $log['id'],
                'log_id' => $log['log_id'],
                'user_id' => $log['user_id'],
                'ip_address' => $log['ip_address'],
                'user_action' => $log['user_action'],
                'details' => $arrWithParentId,
                'user_device' =>  $log['user_device'],
                'created_at' =>  $log['created_at'],
                'updated_at' =>  $log['updated_at'],
                'deleted_at' =>  $log['deleted_at'],
            ];
        }

        return response()->json([
            'message' => 'Successfully Retrieve Data',
            'result' => $decryptedLogs,
        ], Response::HTTP_OK);
    }

    public function isDecryptedData($fields, $fieldsToDecrypt)
    {
        $decryptedData = [];

        // Iterate over each field in the log details
        foreach ($fields as $fieldName => $fieldValue) {
            // Check if the field needs to be decrypted
            if (in_array($fieldName, $fieldsToDecrypt)) {
                // Decrypt the field value and store it in the result array
                $decryptedData[$fieldName] = Crypt::decrypt($fieldValue);
            } else {
                $decryptedData[$fieldName] = $fieldValue;
            }
        }

        return $decryptedData;
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
