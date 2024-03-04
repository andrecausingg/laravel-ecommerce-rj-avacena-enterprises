<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class InventoryProductModel extends Model
{
    use HasFactory;
    protected $table = 'inventory_product_tbl';

    protected $primaryKey = 'id';
    protected $fillable = [
        'inventory_group_id',
        'product_id',
        'item_code',

        'image',
        'name',
        'description',
        'is_refund',
        'category',

        'retail_price',
        'discounted_price',
        'stock',

        'supplier',
        'unit_supplier_price',

        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];
}
