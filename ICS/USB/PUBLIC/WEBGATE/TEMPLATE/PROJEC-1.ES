<HTML>
<!-- Vijeo Web Gate HTTP server -->
<HEAD>
	<TITLE>Vijeo Web Gate</TITLE>
	<link href="html/lib/css/main.css" type="text/css" rel="stylesheet" charset="ISO-8859-1">
	<link href="html/lib/css/static.css" type="text/css" rel="stylesheet" charset="ISO-8859-1">
    <script language="javascript" src="html/config.js" type="text/javascript"></script>
</HEAD>
<BODY>
<table width="100%" border="0">
<tr>
	<td class="title">Estadísticas del proyecto</td>
</tr>
<tr>
<td>
<table class="statictable" width="300px" align="center" rules="all" frame="border">
	<tr><td colspan="2" class="tabletitle">Parámetros del proyecto</td></tr>
	<tr><td class="staticlabel">Tipo de panel</td><td class="staticvalue"><%= project_panel_type %></td></tr>
	<tr><td class="staticlabel">Nombre del proyecto</td><td class="staticvalue"><%= project_name %></td></tr>
	<tr><td class="staticlabel">Nombre del destino</td><td class="staticvalue"><%= project_target_name %></td></tr>
	<tr><td class="staticlabel">Versión del Editor</td><td class="staticvalue"><%= project_editor_version %></td></tr>
	<tr><td class="staticlabel">Versión de Runtime</td><td class="staticvalue"><%= project_runtime_version %></td></tr>
</table>
</td>
</tr>
<tr>
	<td align="center">Copyright (C) <script language="javascript">InsertYears()</script>, Schneider-Electric Industries SAS. Todos los derechos reservados.</td>
</tr>
</table>
</BODY>
</HTML>
