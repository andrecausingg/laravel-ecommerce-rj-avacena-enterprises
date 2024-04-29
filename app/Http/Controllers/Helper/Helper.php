<?php

namespace App\Http\Controllers\Helper;

use App\Models\LogsModel;
use Jenssegers\Agent\Agent;
use App\Models\HistoryModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Http;
use Symfony\Component\HttpFoundation\Response;

class Helper
{
    protected $agent;

    public function __construct(Agent $agent)
    {
        $this->agent = $agent;
    }


    // Authentication
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

    // Unset column dont want to include to save on database
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

    // Uppercase specific data base on validated
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

    // Uppercase the Word with dash -
    public function upperCase($buttonName)
    {
        if ($buttonName == '' || $buttonName == null) {
            return null;
        }
        // Remove hyphens and uppercase the string
        $upperCaseString = str_replace('-', ' ', ucfirst($buttonName));

        return $upperCaseString;
    }

    // Uppercase All the Word with dash - 
    public function transformColumnName($column)
    {
        return ucwords(str_replace('_', ' ', $column));
    }

    public function functionRelative($prefix, $apiWithPayloads, $methods, $buttonNames, $icons, $actions)
    {
        $functions = [];

        foreach ($apiWithPayloads as $key => $payload) {
            // Remove forward slash from the key
            $cleanedKey = rtrim($key, '/');

            $method = $methods[$key] ?? null;
            $functions[$cleanedKey] = [
                'api' => $prefix . $key,
                'payload' => $payload,
                'method' => $method,
                'icon' => $icons[$key],
                'button_name' => $this->upperCase($buttonNames[$key]),
                'action' => $actions[$key],
            ];
        }

        return [$functions];
    }

    public function functionsApiAccountsCrud($prefix, $apiWithPayloads, $methods, $buttonNames, $icons, $actions)
    {
        $functions = [];

        foreach ($apiWithPayloads as $key => $payload) {
            $method = $methods[$key] ?? null;
            $functions[$key] = [
                'api' => $prefix . $key,
                'payload' => $payload,
                'method' => $method,
                'icon' => $icons[$key],
                'button_name' => $this->upperCase($buttonNames[$key]),
                'action' => $actions[$key],
            ];
        }

        return $functions;
    }

    public function log($request, $arr_data_logs)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        if ($arr_data_logs['is_history'] == 1) {
            $history = HistoryModel::create([
                'tbl_id' => $arr_data_logs['log_details']['fields']['user_id'],
                'tbl_name' => 'users_tbl',
                'column_name' => 'password',
                'value' => $arr_data_logs['log_details']['fields']['password'],
            ]);

            // Check if history creation failed
            if (!$history) {
                return response()->json(['message' => 'Failed to store history'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Update history ID
            $history_update = $history->update([
                'history_id' => 'history_id-' . $history->id,
            ]);

            // Check if history update failed
            if (!$history_update) {
                return response()->json(['message' => 'Failed to update history ID'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        $log = LogsModel::create([
            'user_id' => $arr_data_logs['user_id'],
            'is_sensitive' => $arr_data_logs['is_sensitive'],
            'ip_address' => $request->ip(),
            'user_action' => $arr_data_logs['user_action'],
            'user_device' => $userAgent,
            'details' => json_encode($arr_data_logs['log_details'], JSON_PRETTY_PRINT),
        ]);

        if (!$log) {
            return response()->json(['message' => 'Failed to store logs'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $log_update = $log->update([
            'log_id' => 'log_id-'  . $log->id,
        ]);

        // Check if history update failed
        if (!$log_update) {
            return response()->json(['message' => 'Failed to update log ID'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => $arr_data_logs['is_history'] == 1 ? 'Successfully stored logs and history' : 'Successfully stored logs'], Response::HTTP_OK);
    }


    public function userDevice()
    {
        $arr_device_details = [
            'device' => $this->agent->device(),
            'browser' => $this->agent->browser(),
            'platform' => $this->agent->platform()
        ];

        return $arr_device_details;
    }

    // public function fetchDeviceDetails($data)
    // {
    //     if (Browser::isMobile()) {
    //         $device = 'Mobile';
    //     } else if (Browser::isTablet()) {
    //         $device = 'Tablet';
    //     } else {
    //         $device = 'Desktop';
    //     }
    //     $ispProvider = $this->isp_vendor->getUserISP($data->header('remote-ip'));
    //     $device_info = $device . '-' . Browser::browserName() . '-' . Browser::platformName() . '-' . $data->header('remote-ip') . '-' . $ispProvider->isp;

    //     return response()->json(["message" => _("User device information"), "data" => ['device' => $device_info, 'ip' => $data->ip(), 'isp' => $ispProvider->isp]]);
    // }

    // public function getUserISP($ip)
    // {
    //     $response = Http::get("http://ip-api.com/json/{$ip}");

    //     if ($response->successful()) {
    //         return $response->json();
    //     } else {
    //         // Handle unsuccessful response
    //         return null;
    //     }
    // }
}
