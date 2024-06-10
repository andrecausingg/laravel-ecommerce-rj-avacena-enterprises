<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class InventoryProductModel extends Model
{
    use HasFactory;
    use SoftDeletes;
    protected $table = 'inventory_product_tbl';

    protected $primaryKey = 'id';
    protected $fillable = [
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
        'unit_supplier_price',

        'stocks',

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
        return [
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
            'unit_supplier_price',
            'stocks',
        ];
    }
    public function arrToUpdates(): array
    {
        return [
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
            'unit_supplier_price',
            'stocks',
        ];
    }

    public function arrToDeletes(): array
    {
        return [
            'inventory_product_id',
            'inventory_id',
            'eu_device',
        ];
    }

    public function unsetActions(): array
    {
        return [
            'delete',
        ];
    }

    public function idToUpdate(): array
    {
        return [
            'inventory_product_id' => 'inventory_product_id-',
        ];
    }

    public function arrModelWithId(): array
    {
        return [
            'PurchaseModel'  => ['inventory_product_id',]
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'inventory/product/';
        $payload = [
            'update' => [
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
                'unit_supplier_price',
                'stocks',
                'eu_device'
            ],
            'destroy' => ['inventory_product_id', 'eu_device']
        ];
        $method = [
            'update' => 'POST',
            'destroy' => 'DELETE',
        ];
        $button_name = [
            'update' => 'edit',
            'destroy' => 'delete',
        ];
        $icon = [
            'update' => "radix-icons:pencil-1",
            'destroy' =>  "radix-icons:trash",
        ];
        $container = [
            'update' => 'modal',
            'destroy' => 'modal',
        ];

        return compact('prefix', 'payload', 'method', 'button_name', 'icon', 'container');
    }

    public function getApiAccountRelativeSettings()
    {
        $prefix = 'inventory/product/';
        $payload = [
            'store' => [
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
                'unit_supplier_price',
                'stocks',
                'eu_device'
            ]
        ];

        $method = [
            'store' => 'POST',
        ];

        $button_name = [
            'store' => 'create',
        ];

        $icon = [
            'store' => null,
        ];

        $container = [
            'store' => 'modal',
        ];

        return compact('prefix', 'payload', 'method', 'button_name', 'icon', 'container');
    }

    public function arrToConvertToReadableDateTime(): array
    {
        return  [
            'created_at', 'updated_at', 'deleted_at'
        ];
    }

    public function arrDetails(): array
    {
        return [
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
            'unit_supplier_price',
            'stocks',
        ];
    }


    public function getViewRowTable()
    {
        // $prefix = 'inventory/product/';
        // $url = $prefix . 'show/';
        $url = '';
        $method = 'GET';
        return compact('url',  'method');
    }

    public function getArrFieldsToAppend(): array
    {
        return [
            'category',
        ];
    }

    public function arrColumns(): array
    {
        return [
            'item_code',
            'image', 
            'name', 
            'category', 
            'retail_price', 
            'discounted_price', 
            'sells', 
            'stocks', 
        ];
    }
}
