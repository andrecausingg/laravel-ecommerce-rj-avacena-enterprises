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
        'group_id',
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
            'group_id' => 'inv_gro_id-',
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
            'destroy',
        ];
    }

    public function arrHaveAtConvertToReadDateTime(): array
    {
        return  [
            'created_at', 'updated_at', 'deleted_at'
        ];
    }

    public function arrModelWithId(): array
    {
        return [
            'InventoryProductModel'  => ['inventory_id', 'inventory_group_id']
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'inventory/parent/';
        $apiWithPayloads = [
            'update' => $this->arrToUpdates(),
            'destroy' => ['user_id', 'eu_device']
        ];
        $methods = [
            'update' => 'POST',
            'destroy' => 'DELETE',
        ];
        $buttonNames = [
            'update' => 'update',
            'destroy' => 'delete',
        ];
        $icons = [
            'update' => null,
            'destroy' =>  null,
        ];
        $actions = [
            'update' => 'modal',
            'destroy' => 'modal',
        ];

        return compact('prefix', 'apiWithPayloads', 'methods', 'buttonNames', 'icons', 'actions');
    }

    public function getApiAccountRelativeSettings()
    {
        $prefix = 'inventory/parent/';
        $apiWithPayloads = [
            'store' => $this->arrToStores(),
            'show/' => [
                'id',
            ]
        ];

        $methods = [
            'store' => 'POST',
            'show/' => 'GET',
        ];

        $buttonNames = [
            'store' => 'create',
            'show/' => null,
        ];

        $icons = [
            'store' => null,
            'show/' => null,
        ];

        $actions = [
            'store' => 'modal',
            'show/' => null,
        ];

        return compact('prefix', 'apiWithPayloads', 'methods', 'buttonNames', 'icons', 'actions');
    }
}
