<?php

namespace App\Http\Controllers;

use App\Models\UserInfoModel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;

use Symfony\Component\HttpFoundation\Response;

class UserInfoController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $decryptedUserInfos = [];

        $userInfos = UserInfoModel::all();

        foreach ($userInfos as $userInfo) {
            $decryptedUserInfo = [
                'id' => $userInfo && $userInfo->id ? $userInfo->id : null,
                'user_id_hash' => $userInfo && $userInfo->user_id_hash ? $userInfo->user_id_hash : null,
                'first_name' => $userInfo && $userInfo->first_name ? Crypt::decrypt($userInfo->first_name) : null,
                'middle_name' => $userInfo && $userInfo->middle_name ? Crypt::decrypt($userInfo->middle_name) : null,
                'last_name' => $userInfo && $userInfo->last_name ? Crypt::decrypt($userInfo->last_name) : null,
                'contact_number' => $userInfo && $userInfo->contact_number ? Crypt::decrypt($userInfo->contact_number) : null,
                'email' => $userInfo && $userInfo->email ? Crypt::decrypt($userInfo->email) : null,
                'address_1' => $userInfo && $userInfo->address_1 ? Crypt::decrypt($userInfo->address_1) : null,
                'address_2' => $userInfo && $userInfo->address_2 ? Crypt::decrypt($userInfo->address_2) : null,
                'region_code' => $userInfo && $userInfo->region_code ? Crypt::decrypt($userInfo->region_code) : null,
                'province_code' => $userInfo && $userInfo->province_code ? Crypt::decrypt($userInfo->province_code) : null,
                'city_or_municipality_code' => $userInfo && $userInfo->city_or_municipality_code ? Crypt::decrypt($userInfo->city_or_municipality_code) : null,
                'region_name' => $userInfo && $userInfo->region_name ? Crypt::decrypt($userInfo->region_name) : null,
                'province_name' => $userInfo && $userInfo->province_name ? Crypt::decrypt($userInfo->province_name) : null,
                'city_or_municipality_name' => $userInfo && $userInfo->city_or_municipality_name ? Crypt::decrypt($userInfo->city_or_municipality_name) : null,
                'barangay' => $userInfo && $userInfo->barangay ? Crypt::decrypt($userInfo->barangay) : null,
                'description_location' => $userInfo && $userInfo->description_location ? Crypt::decrypt($userInfo->description_location) : null,
            ];

            $decryptedUserInfos[] = $decryptedUserInfo;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $decryptedUserInfos,
            ],
            Response::HTTP_OK
        );
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
