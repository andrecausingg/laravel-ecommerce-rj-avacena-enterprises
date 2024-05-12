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
        'inventory_id',
        'name',
        'category',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function idToUpdate(): array
    {
        return [
            'inventory_id' => 'inv_id-',
        ];
    }

    public function arrToStores(): array
    {
        return [
            'name', 'category'
        ];
    }

    public function arrToUpdates(): array
    {
        return [
            'name', 'category'
        ];
    }

    public function unsetActions(): array
    {
        return [
            'delete',
        ];
    }

    public function arrToConvertToReadableDateTime(): array
    {
        return  [
            'created_at', 'updated_at', 'deleted_at'
        ];
    }

    public function arrModelWithId(): array
    {
        return [
            'InventoryProductModel'  => ['inventory_id']
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'inventory/parent/';
        $payloads = [
            'update' => ['inventory_id', 'name', 'category'],
            'destroy' => ['inventory_id', 'eu_device']
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
        $action = [
            'update' => 'modal',
            'destroy' => 'modal',
        ];

        return compact('prefix', 'payloads', 'method', 'button_name', 'icon', 'action');
    }

    public function getApiAccountRelativeSettings()
    {
        $prefix = 'inventory/parent/';
        $payloads = [
            'store' => $this->arrToStores(),
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

        $action = [
            'store' => 'modal',
        ];

        return compact('prefix', 'payloads', 'method', 'button_name', 'icon', 'action');
    }

    public function getViewRowTable()
    {
        $prefix = 'inventory/parent';

        $url = $prefix . 'product/show/';
        $method = 'GET';
        return compact('url',  'method');
    }

    public function arrDetails(): array
    {
        return [
            'name', 'category'
        ];
    }
}
