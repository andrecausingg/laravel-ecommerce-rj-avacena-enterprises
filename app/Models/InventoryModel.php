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
}
