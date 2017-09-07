/*  processdumper: console utility for software analysis
 *  Copyright(C) 2017  Peter Bohning
 *  This program is free software : you can redistribute it and / or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "functionprototypes.h"
#include "hook.h"
#include "logging.h"
#include "argspecutil.h"

//changed to only reorder if... 
void insert_arg_spec(struct arg_spec * a, struct arg_spec * r, struct arg_spec * q)
{
	struct arg_spec *b, *c;
	int found_r = 0;
	if(a == q || q->next_spec == r)
		return;
	b = q->next_spec;
	while(a)
	{
		c = a->next_spec;
		if(c == q)
		{
			if(!found_r)
				return;
			a->next_spec = b;
			a = b;
		}
		else if(c == r)
		{
			a->next_spec = q;
			q->next_spec = r;
			a = r;
			found_r = 1;
		}
		else
			a = c;
	}
}

void zero_val_vals(struct arg_spec * a)
{
	while(a)
	{
		if(a->deref)
			zero_val_vals(a->deref);
		a->val_val = 0;
		a = a->next_spec;
	}
}

struct arg_spec * deref_end(struct arg_spec * s)
{
	if(s->deref)
		return deref_end(s->deref);
	else
		return s;
}

struct arg_spec * get_container_by_deref(struct arg_spec * cont, struct arg_spec * s, struct arg_spec * e)
{
	struct arg_spec * s2;
	while(s && s != e)
	{
		if(s->deref)
		{
			s2 = get_container_by_deref(s, s->deref, e);
			if(s2)
				return s2;
		}
		s = s->next_spec;
	}
	if(s == e)
		return cont;
	return NULL;
}

/* Cleans up all arguments to a function */
void cleanup_arg_spec(struct arg_spec * arg_spec)
{
	struct arg_spec * as;

	while(arg_spec)
	{
		as = arg_spec->next_spec;
		if(arg_spec->arg_name)
			free_0(arg_spec->arg_name);
		cleanup_arg_spec(arg_spec->deref);
		free_0(arg_spec);
		arg_spec = as;
	}
}