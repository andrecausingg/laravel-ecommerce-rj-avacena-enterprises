<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class InventoryModel extends Model
{
    use HasFactory;
    use SoftDeletes;
    protected $table = 'inventory_tbl';

    protected $primaryKey = 'id';
    protected $fillable = [
        'product_id',
        'group_product_id',

        'parent_name',
        'parent_category',
        'role',
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

        'deleted_at',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];
}
