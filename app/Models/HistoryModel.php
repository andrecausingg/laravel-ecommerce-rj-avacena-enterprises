<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class HistoryModel extends Model
{
    use HasFactory;
    protected $table = 'history_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'history_id',
        'tbl_id',
        'tbl_name',
        'column_name',
        'value',
        'created_at',
        'updated_at',
    ];
    use SoftDeletes;
}
