<?php 

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Model;	

class Category extends Model{
	//lista todas as categorias 
	public function listAll(){

		$sql = new Sql();

		return $sql->select("SELECT * FROM tb_categories ORDER BY descategory");
	}
	//create save
	public function save(){

		$sql = new Sql();
		$results = $sql->select("CALL sp_categories_save(:idcategory, :descategory)", array(
			":idcategory"=>$this->getidcategory(),
			":descategory"=>$this->getdescategory()
		));

		$this->setData($results[0]);

		Category::updateFile();
	}		
	//Get id
	public function get($idcategory){

		$sql = new Sql();
		$results = $sql->select("SELECT * FROM tb_categories WHERE idcategory = :idcategory", [
			':idcategory'=>$idcategory
		]);

		$this->setData($results[0]);
	}	
	//delete a partir do id 
	public function delete(){

		$sql = new Sql();
		$sql->query("DELETE FROM tb_categories WHERE idcategory = :idcategory", [
			':idcategory'=>$this->getidcategory()
		]);		

		Category::updateFile();
	}	
	//montagem tabela dinamica Categorias - Home 
	public function updateFile(){

		$categories = Category::listAll(); //listar todas as categorias

		$html = [];

		foreach ($categories as $row) {
			array_push($html, '<li><a href="/categories/'. $row['idcategory'].'">'. $row['descategory'].'</a></li>');
		}

		file_put_contents($_SERVER['DOCUMENT_ROOT'] . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . "categories-menu.html", implode('', $html));
	}
}
?>