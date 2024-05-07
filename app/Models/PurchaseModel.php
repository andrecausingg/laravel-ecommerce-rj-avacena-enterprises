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
        'inventory_group_id',
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
            'inventory_group_id',
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
            'inventory_group_id',
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
}
