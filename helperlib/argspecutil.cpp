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

void insert_arg_spec(struct arg_spec * a, struct arg_spec * r, struct arg_spec * q)
{
	struct arg_spec *b, *c;
	if(q->next_spec == r)
		return;
	b = q->next_spec;
	while(a)
	{
		c = a->next_spec;
		if(c == q)
		{
			a->next_spec = b;
			a = b;
		}
		else if(c == r)
		{
			a->next_spec = q;
			q->next_spec = r;
			a = r;
		}
		else
			a = c;
	}
}

struct arg_spec * copy_arg_spec_chain(struct arg_spec * s)
{
	struct arg_spec * r, *ri;

	r = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
	memcpy_0(r, s, sizeof(struct arg_spec));
	ri = r;
	ri->arg_name = NULL;
	ri->deref_len = NULL;
	s = s->deref;
	while(s)
	{
		ri->deref = (struct arg_spec *)malloc_0(sizeof(struct arg_spec));
		memcpy_0(ri->deref, s, sizeof(struct arg_spec));
		// we do not want copies of these strings... we don't even use them
		//end deref can set the arg_name on the first arg_spec if it wants... 
		ri->deref->arg_name = NULL;
		ri->deref->deref_len = NULL;
		ri = ri->deref;
		s = s->deref;
	}
	return r;
}

struct arg_spec * deref_end(struct arg_spec * s)
{
	if(s->deref)
		return deref_end(s->deref);
	else
		return s;
}

struct arg_spec * get_prev_arg_spec_deref(struct arg_spec * s, struct arg_spec * e)
{
	while(s != e)
	{
		if(s->deref == e)
			return s;
		s = s->deref;
	}
	logPrintf("ERROR: Can't get previous arg_spec deref!!\n");
	return NULL;
}

void cleanup_arg_spec_deref(struct arg_spec * arg_spec)
{
	struct arg_spec * as;

	while(arg_spec)
	{
		as = arg_spec->deref;
		if(arg_spec->arg_name)
			free_0(arg_spec->arg_name);
		if(arg_spec->next_spec)				//DEBUG
			logPrintf("ERROR: arg_spec deref with next_spec!!\n");
		free_0(arg_spec);
		arg_spec = as;
	}
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
		cleanup_arg_spec_deref(arg_spec->deref);			//must be deref since we free here besides... 
		free_0(arg_spec);
		arg_spec = as;
	}
}