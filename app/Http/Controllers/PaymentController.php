<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class PaymentController extends Controller
{

    protected $helper;

    public function __construct(Helper $helper)
    {
        $this->helper = $helper;
    }


    public function payment(Request $request)
    {
        $status = 'DONE';

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'money' => 'required|numeric|min:1',
            'payment_id' => 'required|string',
            'user_id' => 'required|string',
            'purchase_group_id' => 'required|string',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(
                [
                    'message' => $validator->errors(),
                ],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        $decrypted_payment_id = Crypt::decrypt($request->payment_id);
        $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
        $decrypted_user_id_customer = Crypt::decrypt($request->user_id);

        $payment = PaymentModel::where('payment_id', $decrypted_payment_id)
            ->where('user_id', $decrypted_user_id_customer)
            ->where('purchase_group_id', $decrypted_purchase_group_id)
            ->first();

        if (!$payment) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        if ($payment->total_amount > $request->money) {
            return response()->json(['message' => 'Please input an amount greater than your purchase total amount.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $paying = $payment->update([
            'money' => $request->money,
            'change' => $request->money - $payment->total_amount,
            'status' => $status,
        ]);

        if (!$paying) {
            return response()->json(['message' => 'Failed to paid purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $payment = PurchaseModel::where('user_id_customer', $decrypted_user_id_customer)
            ->where('purchase_group_id',  $decrypted_purchase_group_id)
            ->update([
                'status' => $status
            ]);

        if (!$payment) {
            return response()->json(['message' => 'Failed to paid purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Purchase successfully paid.'], Response::HTTP_OK);
    }

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
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
