<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class HistoryModel extends Model
{
    use HasFactory;
    protected $table = 'history_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'user_id_hash',
        'password',
        'tbl_name',
        'column_name',
        'value',
        'created_at',
        'updated_at',
    ];
}
