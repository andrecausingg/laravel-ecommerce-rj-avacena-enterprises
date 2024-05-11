<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class PurchaseModel extends Model
{
    use HasFactory, SoftDeletes;
    protected $table = 'purchase_tbl';
    protected $primaryKey = 'id';
    protected  $fillable = [
        'purchase_id',
        'purchase_group_id',

        'user_id_customer',
        'user_id_ecom',
        'user_id_menu',

        'inventory_product_id',
        'inventory_id',
        'item_code',

        'image',
        'name',
        'category',
        'description',
        'supplier_name',
        'design',
        'size',
        'color',

        'retail_price',
        'discounted_price',

        'status',

        'deleted_at',
        'created_at',
        'updated_at',
    ];

    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function arrToStores(): array
    {
        return  [
            'purchase_id',
            'purchase_group_id',

            'user_id_customer',
            'user_id_menu',

            'inventory_product_id',
            'inventory_id',
            'item_code',

            'image',
            'name',
            'category',
            'description',
            'supplier_name',
            'design',
            'size',
            'color',

            'retail_price',
            'discounted_price',

            'status',
        ];
    }

    public function arrAddQtyPurchases(): array
    {
        return  [
            'purchase_group_id',

            'user_id_customer',
            'user_id_ecom',
            'user_id_menu',

            'inventory_product_id',
            'inventory_id',
            'item_code',

            'image',
            'name',
            'category',
            'description',
            'supplier_name',
            'design',
            'size',
            'color',

            'retail_price',
            'discounted_price',

            'status',
        ];
    }

    public function idToUpdatePurchase(): array
    {
        return [
            'purchase_id' => 'purchase_id-',
        ];
    }

    public function idToUpdatePayment(): array
    {
        return [
            'payment_id' => 'payment_id-',
        ];
    }

    public function arrPurchaseData(): array
    {
        return [
            'purchase_id',
            'purchase_group_id',
            'user_id_customer',
            'inventory_id',
            'inventory_product_id',
            'item_code',
            'name',
            'category',
            'design',
            'size',
            'color',
            'retail_price',
            'discounted_price',
            'count',
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'purchase/';
        $api_with_payloads = [
            'minus-qty' => [
                'purchase_id',
                'purchase_group_id',
                'inventory_id',
                'inventory_product_id',
                'user_id_customer',
                'eu_device',
            ],
            'add-qty' => [
                'purchase_id',
                'purchase_group_id',
                'inventory_id',
                'inventory_product_id',
                'user_id_customer',
                'eu_device',
            ],
            'delete-all' => [
                'purchase_id',
                'purchase_group_id',
                'user_id_customer',
                'eu_device',
            ]
        ];
        $methods = [
            'minus-qty' => 'POST',
            'add-qty' => 'POST',
            'delete-all' => 'POST',
        ];
        $button_names = [
            'minus-qty' => 'minus qty',
            'add-qty' => 'add qty',
            'delete-all' => 'delete',
        ];
        $icons = [
            'minus-qty' => null,
            'add-qty' => null,
            'delete-all' => null,
        ];
        $actions = [
            'minus-qty' => null,
            'add-qty' => null,
            'delete-all' => null,
        ];

        $prefix = 'purchase/';

        return compact('prefix', 'api_with_payloads', 'methods', 'button_names', 'icons', 'actions');
    }
}
