<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class PaymentController extends Controller
{


    protected $helper, $fillable_attr_purchase, $fillable_attr_inventory_product, $fillable_attr_payment;

    public function __construct(Helper $helper, PurchaseModel $fillable_attr_purchase, InventoryProductModel $fillable_attr_inventory_product, PaymentModel $fillable_attr_payment)
    {
        $this->helper = $helper;
        $this->fillable_attr_purchase = $fillable_attr_purchase;
        $this->fillable_attr_inventory_product = $fillable_attr_inventory_product;
        $this->fillable_attr_payment = $fillable_attr_payment;
    }
    public function dashboard(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }



        return response()->json([
            'message' => 'Successfully get dashboard data.',
            'stock' => $this->getTotalStock(),
            'sale' => $this->getSaleTodayMonthYear(),
            'today_transaction' =>  $this->getTodayTransaction()
        ], Response::HTTP_OK);
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
            ->where('status', 'NOT PAID')
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
            'paid_at' => Carbon::now()
        ]);

        if (!$paying) {
            return response()->json(['message' => 'Failed to paid purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $payment = PurchaseModel::where('user_id_customer', $decrypted_user_id_customer)
            ->where('purchase_group_id',  $decrypted_purchase_group_id)
            ->update([
                'status' => $status,
            ]);

        if (!$payment) {
            return response()->json(['message' => 'Failed to paid purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Purchase successfully paid.'], Response::HTTP_OK);
    }

    private function getTotalStock()
    {
        // Get the sum of inventory products
        $inventory_product_sum = InventoryProductModel::sum('stock');

        return $inventory_product_sum;
    }

    private function getSaleTodayMonthYear()
    {
        $arr_sale = [];

        // Get the current month's sales total
        $arr_sale['month']['current'] = PaymentModel::whereYear('paid_at', now()->year)
            ->whereMonth('paid_at', now()->month)
            ->sum('total_amount');

        // Get the previous month's sales total
        $arr_sale['month']['previous'] = PaymentModel::whereYear('paid_at', now()->subMonth()->year)
            ->whereMonth('paid_at', now()->subMonth()->month)
            ->sum('total_amount');

        // Calculate the percentage increase or decrease for monthly sales
        if ($arr_sale['month']['previous'] != 0) {
            $arr_sale['month']['percent_change'] = (($arr_sale['month']['current'] - $arr_sale['month']['previous']) / abs($arr_sale['month']['previous'])) * 100;
        } else {
            $arr_sale['month']['percent_change'] = ($arr_sale['month']['current'] != 0) ? 100 : 0;
        }

        // Get the current year's sales total
        $arr_sale['year']['current'] = PaymentModel::whereYear('paid_at', now()->year)
            ->sum('total_amount');

        // Get the previous year's sales total
        $arr_sale['year']['previous'] = PaymentModel::whereYear('paid_at', now()->subYear()->year)
            ->sum('total_amount');

        // Calculate the percentage increase or decrease for yearly sales
        if ($arr_sale['year']['previous'] != 0) {
            $arr_sale['year']['percent_change'] = (($arr_sale['year']['current'] - $arr_sale['year']['previous']) / abs($arr_sale['year']['previous'])) * 100;
        } else {
            $arr_sale['year']['percent_change'] = ($arr_sale['year']['current'] != 0) ? 100 : 0;
        }

        // Get today's sales total
        $arr_sale['today']['current'] = PaymentModel::whereDate('paid_at', now()->toDateString())
            ->sum('total_amount');

        return [$arr_sale];
    }
    private function getTodayTransaction()
    {
        $arr_today_transaction = [];

        // Get today's Transaction
        $today_transactions = PaymentModel::whereDate('paid_at', now()->toDateString())->get()->toArray();

        // Assuming $this->fillable_attr_payment->getTodaysTranction() returns an array of attributes to fetch
        foreach ($this->fillable_attr_payment->getTodaysTranction() as $attribute) {
            // Check if the attribute exists in the payment model
            if (array_key_exists($attribute, $today_transactions[0])) {
                $arr_today_transaction[$attribute] = $today_transactions[0][$attribute];

                // Check if the column needs formatting and value is not null
                if (in_array($attribute, $this->fillable_attr_payment->arrToConvertToReadableDateTime()) && $arr_today_transaction[$attribute] !== null) {
                    $arr_today_transaction[$attribute] = $this->helper->convertReadableTimeDate($arr_today_transaction[$attribute]);
                }
            }
        }

        return $arr_today_transaction;
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
